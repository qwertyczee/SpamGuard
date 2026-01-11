// ============================================================================
// SpamGuard Engine
// Main spam detection orchestrator
// ============================================================================

import type {
    EmailInput,
    SpamAnalysisResult,
    AnalyzerResult,
    SpamGuardConfig,
    ParsedEmail,
} from "./types";
import { DEFAULT_CONFIG } from "./types";
import { parseEmail } from "./parser/email";
import { analyzeHeaders } from "./analyzers/header";
import { analyzeContent } from "./analyzers/content";
import { analyzeUrls } from "./analyzers/url";
import { analyzeHtml } from "./analyzers/html";
import { analyzePatterns } from "./analyzers/pattern";
import { analyzeBayesian } from "./analyzers/bayesian";
import {
    extractUrls,
    extractEmails,
    calculateTextStats,
    extractTextFromHtml,
} from "./utils/text";

export class SpamGuard {
    private config: SpamGuardConfig;

    constructor(config: Partial<SpamGuardConfig> = {}) {
        this.config = { ...DEFAULT_CONFIG, ...config };
    }

    /**
     * Analyze an email for spam indicators
     */
    analyze(input: EmailInput): SpamAnalysisResult {
        const startTime = performance.now();

        // Parse the email
        const email = parseEmail(input);

        // Run all analyzers
        const analyzers: AnalyzerResult[] = [
            analyzeHeaders(email),
            analyzeContent(email),
            analyzeUrls(email),
            analyzeHtml(email),
            analyzePatterns(email),
            analyzeBayesian(email),
        ];

        // Calculate total score
        const totalScore = analyzers.reduce((sum, a) => sum + a.score, 0);

        // Calculate confidence based on how many analyzers contributed
        const contributingAnalyzers = analyzers.filter(
            (a) => a.matches.length > 0,
        ).length;
        const confidence = Math.min(
            contributingAnalyzers / analyzers.length + 0.2,
            1,
        );

        // Determine classification
        let classification: "ham" | "spam" | "probable_spam" | "probable_ham";
        const isSpam = totalScore >= this.config.spamThreshold;

        if (totalScore >= this.config.spamThreshold) {
            classification = "spam";
        } else if (totalScore >= this.config.probableSpamThreshold) {
            classification = "probable_spam";
        } else if (totalScore <= 1) {
            classification = "ham";
        } else {
            classification = "probable_ham";
        }

        // Get top reasons
        const allMatches = analyzers
            .flatMap((a) => a.matches)
            .filter((m) => m.matched && m.rule.score > 0)
            .sort((a, b) => b.rule.score - a.rule.score);

        const topReasons = allMatches
            .slice(0, 5)
            .map(
                (m) =>
                    `${m.rule.name}: ${m.rule.description}${m.details ? ` (${m.details})` : ""}`,
            );

        const processingTimeMs = performance.now() - startTime;

        // Build result
        const result: SpamAnalysisResult = {
            isSpam,
            score: Math.round(totalScore * 100) / 100,
            threshold: this.config.spamThreshold,
            confidence: Math.round(confidence * 100) / 100,
            classification,
            analyzers,
            topReasons,
            processingTimeMs: Math.round(processingTimeMs * 100) / 100,
        };

        // Add debug info if enabled
        if (this.config.enableDebug) {
            const textBody = email.textBody || "";
            const htmlText = email.htmlBody
                ? extractTextFromHtml(email.htmlBody)
                : "";
            const allText = `${email.subject} ${textBody} ${htmlText}`;

            result.debug = {
                extractedUrls: extractUrls(allText),
                extractedEmails: extractEmails(allText),
                textStats: calculateTextStats(allText),
            };
        }

        return result;
    }

    /**
     * Quick check - returns just true/false
     */
    isSpam(input: EmailInput): boolean {
        return this.analyze(input).isSpam;
    }

    /**
     * Get spam score only
     */
    getScore(input: EmailInput): number {
        return this.analyze(input).score;
    }

    /**
     * Update configuration
     */
    configure(config: Partial<SpamGuardConfig>): void {
        this.config = { ...this.config, ...config };
    }

    /**
     * Get current configuration
     */
    getConfig(): SpamGuardConfig {
        return { ...this.config };
    }
}

// Export a default instance
export const spamGuard = new SpamGuard();

// Export analyze function for convenience
export function analyzeEmail(
    input: EmailInput,
    config?: Partial<SpamGuardConfig>,
): SpamAnalysisResult {
    const guard = config ? new SpamGuard(config) : spamGuard;
    return guard.analyze(input);
}
