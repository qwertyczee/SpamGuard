// ============================================================================
// Bayesian Analyzer
// Statistical spam classification using token probabilities
// ============================================================================

import type { AnalyzerResult, RuleMatch, ParsedEmail } from "../types";
import {
    BAYESIAN_TOKENS,
    calculateRobinsonFisher,
    tokenize,
} from "../data/bayesian-tokens";
import { extractTextFromHtml } from "../utils/text";

export function analyzeBayesian(email: ParsedEmail): AnalyzerResult {
    const matches: RuleMatch[] = [];

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
                spamProbability: 0.5,
                tokenCount: 0,
                knownTokens: 0,
            },
        };
    }

    // Find tokens with known probabilities
    const knownTokens: Array<{ token: string; spamProb: number }> = [];
    const spamTokens: string[] = [];
    const hamTokens: string[] = [];

    for (const token of tokens) {
        const data = BAYESIAN_TOKENS.get(token);
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
    const spamProbability = calculateRobinsonFisher(tokens);

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
