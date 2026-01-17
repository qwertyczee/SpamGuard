// ============================================================================
// Pattern Analyzer
// Detects obfuscation, encoding tricks, and structural patterns
// Supports multilingual urgency and greeting pattern detection
// ============================================================================

import type { AnalyzerResult, RuleMatch, ParsedEmail } from "../types";
import type { LanguageDataset } from "../data/languages/schema";
import { getEnglishData } from "../data/languages";
import { ALL_PATTERNS } from "../data/patterns";
import {
    extractTextFromHtml,
    hasInvisibleChars,
    hasMixedScripts,
    calculateEntropy,
} from "../utils/text";

/**
 * Options for pattern analysis
 */
export interface PatternAnalyzerOptions {
    /** Language code for urgency/greeting patterns (default: "en") */
    languageCode?: string;
    /** Pre-loaded language dataset (takes precedence over languageCode) */
    languageData?: LanguageDataset;
}

/**
 * Build a regex pattern for urgency words in a given language
 */
function buildUrgencyPattern(urgencyWords: string[]): RegExp | null {
    if (urgencyWords.length === 0) return null;

    // Escape special regex characters in words
    const escapedWords = urgencyWords.map((word) =>
        word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    );

    // Build pattern with word boundaries
    const pattern = `\\b(?:${escapedWords.join("|")})\\b`;

    try {
        return new RegExp(pattern, "gi");
    } catch {
        return null;
    }
}

/**
 * Build a regex pattern for greeting detection
 */
function buildGreetingPattern(greetingWords: string[]): RegExp | null {
    if (greetingWords.length === 0) return null;

    const escapedWords = greetingWords.map((word) =>
        word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    );

    const pattern = `^(?:${escapedWords.join("|")})`;

    try {
        return new RegExp(pattern, "i");
    } catch {
        return null;
    }
}

/**
 * Build a regex pattern for generic greetings
 */
function buildGenericGreetingPattern(genericGreetings: string[]): RegExp | null {
    if (genericGreetings.length === 0) return null;

    const escapedGreetings = genericGreetings.map((g) =>
        g.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    );

    const pattern = `^(?:${escapedGreetings.join("|")})`;

    try {
        return new RegExp(pattern, "i");
    } catch {
        return null;
    }
}

/**
 * Analyze email patterns for spam indicators
 *
 * @param email - Parsed email to analyze
 * @param options - Analysis options including language settings
 * @returns Analysis result with matched patterns
 */
export function analyzePatterns(
    email: ParsedEmail,
    options: PatternAnalyzerOptions = {}
): AnalyzerResult {
    const matches: RuleMatch[] = [];
    let totalScore = 0;

    // Get language dataset (use provided data or fall back to English)
    const langData =
        options.languageData || getEnglishData();

    // Get content to analyze
    const textBody = email.textBody || "";
    const htmlText = email.htmlBody ? extractTextFromHtml(email.htmlBody) : "";
    const allText = `${email.subject} ${textBody} ${htmlText}`;
    const bodyText = (textBody || htmlText || "").trim();

    // Build language-specific patterns
    const urgencyPattern = buildUrgencyPattern(langData.urgencyWords);
    const greetingPattern = buildGreetingPattern(langData.greetingWords);
    const genericGreetingPattern = buildGenericGreetingPattern(langData.genericGreetings);

    for (const pattern of ALL_PATTERNS) {
        // For greeting patterns, check only the body text start
        const textToCheck =
            pattern.name === "NO_GREETING" ||
            pattern.name === "GENERIC_GREETING"
                ? bodyText
                : allText;

        // Skip NO_GREETING for replies/forwards/notifications
        if (pattern.name === "NO_GREETING") {
            const subject = email.subject || "";

            // Skip if subject indicates reply/forward
            if (
                /^(?:re|fwd?|aw|tr|sv):/i.test(subject) ||
                /\[.*?\]/.test(subject)
            ) {
                continue;
            }

            // Skip if body starts with notification-style content
            const firstLine = bodyText.split("\n")[0].trim();

            // Skip if starts with @mention (GitHub, etc.)
            if (firstLine.startsWith("@")) {
                continue;
            }

            // Skip if starts with a phrase commonly found in notifications
            const notificationPatterns = [
                /^(?:you've|you have) (?:been|received|been granted)/i,
                /^(?:your|this) (?:order|invoice|ticket|request|support) /i,
                /^(?:payment|shipping|delivery) (?:is|has|for)/i,
                /^(?:password|account|security) (?:reset|update|notification)/i,
                /^(?:weekly|daily|monthly) (?:digest|summary|report)/i,
                /^(?:new|latest|recent) (?:commit|pull request|issue|PR) /i,
                /^(?:ticket|order|invoice) #/i,
                /^(?:hi|hello) /i, // Any "Hi ..." is a greeting
            ];

            if (notificationPatterns.some((p) => p.test(firstLine))) {
                continue;
            }

            // Also check against language-specific greeting pattern
            if (greetingPattern && greetingPattern.test(firstLine)) {
                continue;
            }

            // Skip if the body starts with a title/header-like line
            // (short line without comma, likely a subject line or header)
            if (
                firstLine.length > 0 &&
                firstLine.length < 50 &&
                !firstLine.includes(",")
            ) {
                continue;
            }
        }

        const match = pattern.pattern.exec(textToCheck);
        if (match) {
            matches.push({
                rule: {
                    name: pattern.name,
                    description: pattern.description,
                    score: pattern.score,
                    category: pattern.category as any,
                },
                matched: true,
                details: pattern.description,
                evidence: [match[0].substring(0, 100)],
            });
            totalScore += pattern.score;
        }
    }

    // Check for generic greetings using language-specific patterns
    if (genericGreetingPattern) {
        const firstLine = bodyText.split("\n")[0].trim().toLowerCase();
        if (genericGreetingPattern.test(firstLine)) {
            matches.push({
                rule: {
                    name: "GENERIC_GREETING_LANG",
                    description: `Generic impersonal greeting detected (${langData.languageName})`,
                    score: 1.2,
                    category: "pattern",
                },
                matched: true,
                details: firstLine.substring(0, 50),
            });
            totalScore += 1.2;
        }
    }

    // Check for invisible characters
    if (hasInvisibleChars(allText)) {
        matches.push({
            rule: {
                name: "INVISIBLE_CHARS",
                description: "Zero-width or invisible characters detected",
                score: 1.0,
                category: "pattern",
            },
            matched: true,
            details: "Text contains invisible Unicode characters",
        });
        totalScore += 1.0;
    }

    // Check for mixed scripts (homograph attack)
    if (hasMixedScripts(allText)) {
        matches.push({
            rule: {
                name: "MIXED_SCRIPTS",
                description:
                    "Multiple Unicode scripts detected (possible homograph attack)",
                score: 1.0,
                category: "pattern",
            },
            matched: true,
            details: "Latin mixed with Cyrillic or Greek characters",
        });
        totalScore += 1.0;
    }

    // Check for random-looking text (high entropy)
    const words = allText.split(/\s+/).filter((w) => w.length > 5);
    let highEntropyWords = 0;
    const uniqueWords = new Set<string>();

    for (const word of words.slice(0, 100)) {
        const lowerWord = word.toLowerCase();
        uniqueWords.add(lowerWord);
        const entropy = calculateEntropy(lowerWord);
        if (entropy > 4.5) {
            highEntropyWords++;
        }
    }

    if (words.length > 20 && highEntropyWords / words.length > 0.4) {
        matches.push({
            rule: {
                name: "WORD_SALAD",
                description:
                    "High ratio of unique words (possible Bayesian poisoning)",
                score: 0.5,
                category: "pattern",
            },
            matched: true,
            details: `${uniqueWords.size} unique words out of ${words.length} total`,
        });
        totalScore += 0.5;
    }

    // Check for repeated phrases (copy-paste spam)
    const sentences = allText
        .split(/[.!?]+/)
        .filter((s) => s.trim().length > 20);
    const sentenceSet = new Set<string>();
    let duplicateSentences = 0;

    for (const sentence of sentences) {
        const normalized = sentence.trim().toLowerCase();
        if (sentenceSet.has(normalized)) {
            duplicateSentences++;
        } else {
            sentenceSet.add(normalized);
        }
    }

    if (sentences.length > 5 && duplicateSentences / sentences.length > 0.3) {
        matches.push({
            rule: {
                name: "CHAR_STUFFING",
                description: "Character repetition detected",
                score: 0.5,
                category: "pattern",
            },
            matched: true,
            details: `${duplicateSentences} repeated sentences detected`,
        });
        totalScore += 0.5;
    }

    // Check for hashbusters (random text at bottom of email)
    const parts = allText.split(/\n{3,}/);
    if (parts.length > 1) {
        const lastPart = parts[parts.length - 1].trim();
        const lastPartEntropy = calculateEntropy(lastPart);

        if (lastPart.length > 100 && lastPartEntropy > 5.0) {
            matches.push({
                rule: {
                    name: "HIGH_ENTROPY_FOOTER",
                    description: "High entropy text at footer",
                    score: 0.5,
                    category: "pattern",
                },
                matched: true,
                details: "Footer matches high entropy patterns",
            });
            totalScore += 0.5;
        }
    }

    // Check for urgency amplifiers using language-specific patterns
    if (urgencyPattern) {
        const urgencyMatches = allText.match(urgencyPattern) || [];

        if (urgencyMatches.length >= 3) {
            matches.push({
                rule: {
                    name: "MULTIPLE_URGENCY",
                    description: `Multiple urgency phrases (${langData.languageName})`,
                    score: 1.0,
                    category: "pattern",
                },
                matched: true,
                details: `${urgencyMatches.length} urgency phrases`,
                evidence: urgencyMatches.slice(0, 5),
            });
            totalScore += 1.0;
        }
    }

    return {
        analyzer: "pattern",
        score: totalScore,
        maxScore: ALL_PATTERNS.reduce((sum, p) => sum + p.score, 0) + 15,
        matches,
        metadata: {
            language: langData.language,
            uniqueWordRatio: uniqueWords.size / Math.max(words.length, 1),
            highEntropyRatio:
                words.length > 0 ? highEntropyWords / words.length : 0,
            duplicateSentences,
        },
    };
}
