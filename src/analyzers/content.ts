// ============================================================================
// Content Analyzer
// Analyzes email body content for spam indicators
// ============================================================================

import type {
    AnalyzerResult,
    RuleMatch,
    AnalysisRule,
    ParsedEmail,
} from "../types";
import {
    SPAM_WORDS,
    SPAM_SINGLE_WORDS,
    SPAM_SUBJECT_PATTERNS,
    HAM_WORDS,
} from "../data/spam-words";
import {
    calculateTextStats,
    normalizeText,
    extractTextFromHtml,
} from "../utils/text";

const CONTENT_RULES: AnalysisRule[] = [
    {
        name: "SPAM_PHRASE_MATCH",
        description: "Known spam phrase detected",
        score: 0, // Dynamic based on match
        category: "content",
    },
    {
        name: "SPAM_WORD_MATCH",
        description: "Known spam word detected",
        score: 0, // Dynamic
        category: "content",
    },
    {
        name: "HAM_PHRASE_MATCH",
        description: "Known legitimate phrase detected",
        score: 0, // Dynamic (negative)
        category: "content",
    },
    {
        name: "SUBJECT_SPAM_PATTERN",
        description: "Spam pattern in subject",
        score: 0, // Dynamic
        category: "content",
    },
    {
        name: "HIGH_CAPS_RATIO",
        description: "Too much uppercase text",
        score: 0.5,
        category: "content",
    },
    {
        name: "HIGH_SPECIAL_CHAR_RATIO",
        description: "Too many special characters",
        score: 0.5,
        category: "content",
    },
    {
        name: "EMPTY_BODY",
        description: "Empty or very short body",
        score: 1.0,
        category: "content",
    },
    {
        name: "BODY_HTML_ONLY",
        description: "HTML-only body with no text alternative",
        score: 0.5,
        category: "content",
    },
    {
        name: "SUBJECT_EMPTY",
        description: "Empty subject line",
        score: 1.0,
        category: "content",
    },
    {
        name: "SUBJECT_ALL_CAPS",
        description: "Subject line is all caps",
        score: 1.0,
        category: "content",
    },
    {
        name: "MULTIPLE_EXCLAMATIONS",
        description: "Multiple exclamation marks",
        score: 0.5,
        category: "content",
    },
    {
        name: "EXCESSIVE_MONEY_REFS",
        description: "Multiple money references",
        score: 0.5,
        category: "content",
    },
];

export function analyzeContent(email: ParsedEmail): AnalyzerResult {
    const matches: RuleMatch[] = [];
    let totalScore = 0;

    // Get text content
    const textBody = email.textBody || "";
    const htmlBody = email.htmlBody || "";
    const htmlText = htmlBody ? extractTextFromHtml(htmlBody) : "";

    // Use the richer content source
    const bodyText = textBody.length > htmlText.length ? textBody : htmlText;
    const normalizedBody = normalizeText(bodyText);
    const normalizedSubject = normalizeText(email.subject);

    // Combined text for analysis
    const allText = `${email.subject} ${bodyText}`;
    const normalizedAll = normalizeText(allText);

    // Check for empty body
    if (bodyText.trim().length < 10) {
        const rule = CONTENT_RULES.find((r) => r.name === "EMPTY_BODY")!;
        matches.push({
            rule,
            matched: true,
            details: `Body length: ${bodyText.length}`,
        });
        totalScore += rule.score;
    }

    // Check HTML-only
    if (htmlBody && !textBody) {
        const rule = CONTENT_RULES.find((r) => r.name === "BODY_HTML_ONLY")!;
        matches.push({
            rule,
            matched: true,
            details: "No plain text alternative",
        });
        totalScore += rule.score;
    }

    // Check empty subject
    if (!email.subject || email.subject.trim().length === 0) {
        const rule = CONTENT_RULES.find((r) => r.name === "SUBJECT_EMPTY")!;
        matches.push({ rule, matched: true });
        totalScore += rule.score;
    }

    // Check all caps subject
    if (email.subject && email.subject.length > 5) {
        const letters = email.subject.replace(/[^a-zA-Z]/g, "");
        const upperLetters = email.subject.replace(/[^A-Z]/g, "");

        if (letters.length > 5 && upperLetters.length / letters.length > 0.8) {
            const rule = CONTENT_RULES.find(
                (r) => r.name === "SUBJECT_ALL_CAPS",
            )!;
            matches.push({ rule, matched: true, details: email.subject });
            totalScore += rule.score;
        }
    }

    // Check subject spam patterns
    for (const pattern of SPAM_SUBJECT_PATTERNS) {
        if (pattern.pattern.test(email.subject)) {
            matches.push({
                rule: {
                    name: `SUBJECT_PATTERN_${pattern.name}`,
                    description: `Subject matches spam pattern: ${pattern.name}`,
                    score: pattern.score,
                    category: "content",
                },
                matched: true,
                details: email.subject,
            });
            totalScore += pattern.score;
        }
    }

    // Check spam phrases
    const matchedPhrases: string[] = [];
    for (const spamWord of SPAM_WORDS) {
        const searchTerm = spamWord.caseSensitive
            ? spamWord.word
            : spamWord.word.toLowerCase();
        const textToSearch = spamWord.caseSensitive ? allText : normalizedAll;

        if (textToSearch.includes(searchTerm)) {
            matchedPhrases.push(spamWord.word);
            matches.push({
                rule: {
                    name: `SPAM_PHRASE_${spamWord.category.toUpperCase()}`,
                    description: `Spam phrase: "${spamWord.word}"`,
                    score: spamWord.score,
                    category: "content",
                },
                matched: true,
                details: `Category: ${spamWord.category}`,
                evidence: [spamWord.word],
            });
            totalScore += spamWord.score;
        }
    }

    // Check single spam words
    const words = normalizedAll.split(/\s+/);
    const matchedWords: string[] = [];

    for (const word of words) {
        const score = SPAM_SINGLE_WORDS.get(word);
        if (score && !matchedWords.includes(word)) {
            matchedWords.push(word);
            matches.push({
                rule: {
                    name: "SPAM_WORD_MATCH",
                    description: `Spam word: "${word}"`,
                    score,
                    category: "content",
                },
                matched: true,
                evidence: [word],
            });
            totalScore += score;
        }
    }

    // Check ham words (reduce score)
    for (const [hamWord, adjustment] of HAM_WORDS) {
        if (normalizedAll.includes(hamWord)) {
            matches.push({
                rule: {
                    name: "HAM_PHRASE_MATCH",
                    description: `Legitimate phrase: "${hamWord}"`,
                    score: adjustment,
                    category: "content",
                },
                matched: true,
                evidence: [hamWord],
            });
            totalScore += adjustment; // Negative value
        }
    }

    // Calculate text statistics
    const stats = calculateTextStats(bodyText);

    // High caps ratio
    if (stats.uppercaseRatio > 0.3 && stats.wordCount > 20) {
        const rule = CONTENT_RULES.find((r) => r.name === "HIGH_CAPS_RATIO")!;
        matches.push({
            rule,
            matched: true,
            details: `${(stats.uppercaseRatio * 100).toFixed(1)}% uppercase`,
        });
        totalScore += rule.score;
    }

    // High special char ratio
    if (stats.specialCharRatio > 0.15) {
        const rule = CONTENT_RULES.find(
            (r) => r.name === "HIGH_SPECIAL_CHAR_RATIO",
        )!;
        matches.push({
            rule,
            matched: true,
            details: `${(stats.specialCharRatio * 100).toFixed(1)}% special chars`,
        });
        totalScore += rule.score;
    }

    // Multiple exclamation marks
    const exclamationCount = (allText.match(/!/g) || []).length;
    if (exclamationCount > 5) {
        const rule = CONTENT_RULES.find(
            (r) => r.name === "MULTIPLE_EXCLAMATIONS",
        )!;
        matches.push({
            rule,
            matched: true,
            details: `${exclamationCount} exclamation marks`,
        });
        totalScore += rule.score;
    }

    // Money references
    const moneyPattern =
        /\$\s*[\d,]+(?:\.\d{2})?|\d+\s*(?:dollars?|USD|EUR|GBP)/gi;
    const moneyMatches = allText.match(moneyPattern) || [];
    if (moneyMatches.length > 3) {
        const rule = CONTENT_RULES.find(
            (r) => r.name === "EXCESSIVE_MONEY_REFS",
        )!;
        matches.push({
            rule,
            matched: true,
            details: `${moneyMatches.length} money references`,
            evidence: moneyMatches.slice(0, 5),
        });
        totalScore += rule.score;
    }

    return {
        analyzer: "content",
        score: Math.max(0, totalScore), // Don't go negative
        maxScore: 30, // Approximate max based on possible matches
        matches,
        metadata: {
            wordCount: stats.wordCount,
            capsRatio: stats.uppercaseRatio,
            matchedPhrases: matchedPhrases.length,
            matchedWords: matchedWords.length,
        },
    };
}
