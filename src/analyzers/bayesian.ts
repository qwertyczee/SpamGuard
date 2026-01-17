// ============================================================================
// Bayesian Analyzer
// Statistical spam classification using token probabilities
// Supports multilingual analysis
// ============================================================================

import type { AnalyzerResult, RuleMatch, ParsedEmail } from "../types";
import type { LanguageDataset, TokenProbability } from "../data/languages/schema";
import { getEnglishData } from "../data/languages";
import { extractTextFromHtml } from "../utils/text";

/**
 * Options for Bayesian analysis
 */
export interface BayesianAnalyzerOptions {
    /** Language code for token probabilities (default: "en") */
    languageCode?: string;
    /** Pre-loaded language dataset (takes precedence over languageCode) */
    languageData?: LanguageDataset;
}

/**
 * Tokenize text for Bayesian analysis
 * Language-agnostic tokenization that works for multiple scripts
 */
export function tokenize(text: string): string[] {
    // Simple tokenization - split on non-alphanumeric
    // Extended to support more Unicode ranges for multilingual
    const tokens = text
        .toLowerCase()
        // Keep letters (including accented), numbers, and common punctuation that might be part of words
        .replace(/[^\p{L}\p{N}\s'-]/gu, " ")
        .split(/\s+/)
        .filter((t) => t.length >= 3 && t.length <= 20);

    // Deduplicate while preserving some frequency info
    const tokenCounts = new Map<string, number>();
    for (const token of tokens) {
        tokenCounts.set(token, (tokenCounts.get(token) || 0) + 1);
    }

    // Return unique tokens, but include repeated important ones
    const result: string[] = [];
    for (const [token, count] of tokenCounts) {
        // Add token once, or twice if it appears many times
        result.push(token);
        if (count >= 3) {
            result.push(token);
        }
    }

    return result;
}

/**
 * Calculate spam probability using Robinson-Fisher method
 */
export function calculateRobinsonFisher(
    tokens: string[],
    bayesianTokens: Record<string, TokenProbability>
): number {
    const probabilities: number[] = [];

    for (const token of tokens) {
        const lowerToken = token.toLowerCase();
        const tokenData = bayesianTokens[lowerToken];

        if (tokenData) {
            // Calculate spam probability for this token
            // P(spam|token) = P(token|spam) * P(spam) / P(token)
            // Simplified using equal priors: P(spam|token) = P(token|spam) / (P(token|spam) + P(token|ham))
            const pSpam = tokenData.spam / (tokenData.spam + tokenData.ham);
            probabilities.push(pSpam);
        }
    }

    if (probabilities.length === 0) {
        return 0.5; // Neutral
    }

    // Use the 15 most significant probabilities (furthest from 0.5)
    const significant = probabilities
        .map((p) => ({ p, distance: Math.abs(p - 0.5) }))
        .sort((a, b) => b.distance - a.distance)
        .slice(0, 15)
        .map((x) => x.p);

    const productSpam = significant.reduce((acc, p) => acc * p, 1);
    const productHam = significant.reduce((acc, p) => acc * (1 - p), 1);

    if (productSpam === 0 && productHam === 0) return 0.5; // Avoid 0/0

    const result = productSpam / (productSpam + productHam);

    return Math.max(0, Math.min(1, result));
}

/**
 * Analyze email using Bayesian classification
 *
 * @param email - Parsed email to analyze
 * @param options - Analysis options including language settings
 * @returns Analysis result with spam probability and matched tokens
 */
export function analyzeBayesian(
    email: ParsedEmail,
    options: BayesianAnalyzerOptions = {}
): AnalyzerResult {
    const matches: RuleMatch[] = [];

    // Get language dataset (use provided data or fall back to English)
    const langData =
        options.languageData || getEnglishData();

    // Get all text content
    const textBody = email.textBody || "";
    const htmlText = email.htmlBody ? extractTextFromHtml(email.htmlBody) : "";
    const allText = `${email.subject} ${textBody} ${htmlText}`;

    // Tokenize
    const tokens = tokenize(allText);

    if (tokens.length === 0) {
        return {
            analyzer: "bayesian",
            score: 0,
            maxScore: 5,
            matches: [],
            metadata: {
                language: langData.language,
                spamProbability: 0.5,
                tokenCount: 0,
                knownTokens: 0,
            },
        };
    }

    // Find tokens with known probabilities using language-specific data
    const bayesianTokens = langData.bayesianTokens;
    const knownTokens: Array<{ token: string; spamProb: number }> = [];
    const spamTokens: string[] = [];
    const hamTokens: string[] = [];

    for (const token of tokens) {
        const data = bayesianTokens[token];
        if (data) {
            const spamProb = data.spam / (data.spam + data.ham);
            knownTokens.push({ token, spamProb });

            if (spamProb > 0.7) {
                spamTokens.push(token);
            } else if (spamProb < 0.3) {
                hamTokens.push(token);
            }
        }
    }

    // Calculate overall spam probability
    const spamProbability = calculateRobinsonFisher(tokens, bayesianTokens);

    // Convert probability to score (0-5 range)
    // Probability > 0.5 = spam indicator
    let score = 0;

    if (spamProbability > 0.9) {
        score = 4.0;
    } else if (spamProbability > 0.8) {
        score = 3.0;
    } else if (spamProbability > 0.7) {
        score = 2.0;
    } else if (spamProbability > 0.6) {
        score = 1.0;
    } else if (spamProbability > 0.5) {
        score = 0.5;
    } else if (spamProbability < 0.3) {
        score = -1.0; // Ham indicator
    } else if (spamProbability < 0.2) {
        score = -2.0;
    }

    // Record significant spam tokens
    if (spamTokens.length > 0) {
        matches.push({
            rule: {
                name: "BAYES_SPAM_TOKENS",
                description: "Tokens with high spam probability",
                score: Math.min(spamTokens.length * 0.3, 2.0),
                category: "bayesian",
            },
            matched: true,
            details: `${spamTokens.length} high-probability spam tokens`,
            evidence: [...new Set(spamTokens)].slice(0, 10),
        });
    }

    // Record significant ham tokens
    if (hamTokens.length > 0) {
        matches.push({
            rule: {
                name: "BAYES_HAM_TOKENS",
                description: "Tokens with high ham probability",
                score: -Math.min(hamTokens.length * 0.2, 1.5),
                category: "bayesian",
            },
            matched: true,
            details: `${hamTokens.length} high-probability ham tokens`,
            evidence: [...new Set(hamTokens)].slice(0, 10),
        });
    }

    // Add overall Bayesian verdict
    if (spamProbability > 0.7) {
        matches.push({
            rule: {
                name: "BAYES_SPAM",
                description: `Bayesian classifier indicates spam (${(spamProbability * 100).toFixed(1)}%)`,
                score: score,
                category: "bayesian",
            },
            matched: true,
            details: `Spam probability: ${(spamProbability * 100).toFixed(1)}%`,
        });
    } else if (spamProbability < 0.3) {
        matches.push({
            rule: {
                name: "BAYES_HAM",
                description: `Bayesian classifier indicates ham (${((1 - spamProbability) * 100).toFixed(1)}%)`,
                score: score,
                category: "bayesian",
            },
            matched: true,
            details: `Ham probability: ${((1 - spamProbability) * 100).toFixed(1)}%`,
        });
    }

    // Get most influential tokens
    const sortedTokens = knownTokens
        .map((t) => ({ ...t, distance: Math.abs(t.spamProb - 0.5) }))
        .sort((a, b) => b.distance - a.distance)
        .slice(0, 15);

    return {
        analyzer: "bayesian",
        score: Math.max(0, score),
        maxScore: 5,
        matches,
        metadata: {
            language: langData.language,
            spamProbability,
            tokenCount: tokens.length,
            knownTokens: knownTokens.length,
            spamTokenCount: spamTokens.length,
            hamTokenCount: hamTokens.length,
            mostInfluentialTokens: sortedTokens.map((t) => ({
                token: t.token,
                spamProb: t.spamProb,
            })),
        },
    };
}
