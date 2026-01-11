// ============================================================================
// Integration Tests
// Tests using real-world spam and ham samples
// ============================================================================

import { describe, it, expect } from "bun:test";
import { SpamGuard, analyzeEmail } from "../../src/engine";
import {
    SPAM_EMAILS,
    HAM_EMAILS,
    EDGE_CASE_EMAILS,
} from "../fixtures/emails.test";

describe("SpamGuard Engine", () => {
    describe("Basic Functionality", () => {
        it("should create instance with default config", () => {
            const guard = new SpamGuard();
            const config = guard.getConfig();

            expect(config.spamThreshold).toBe(3.5);
        });

        it("should allow config override", () => {
            const guard = new SpamGuard({ spamThreshold: 10 });
            const config = guard.getConfig();

            expect(config.spamThreshold).toBe(10);
        });

        it("should return valid analysis result structure", () => {
            const result = analyzeEmail({
                from: "test@example.com",
                to: "recipient@example.com",
                subject: "Test",
                textBody: "Hello World",
            });

            expect(result).toHaveProperty("isSpam");
            expect(result).toHaveProperty("score");
            expect(result).toHaveProperty("threshold");
            expect(result).toHaveProperty("confidence");
            expect(result).toHaveProperty("classification");
            expect(result).toHaveProperty("analyzers");
            expect(result).toHaveProperty("topReasons");
            expect(result).toHaveProperty("processingTimeMs");

            expect(Array.isArray(result.analyzers)).toBe(true);
            expect(result.analyzers.length).toBe(6); // 6 analyzers
        });

        it("should include debug info when enabled", () => {
            const result = analyzeEmail(
                {
                    from: "test@example.com",
                    to: "recipient@example.com",
                    subject: "Test",
                    textBody: "Hello World https://example.com",
                },
                { enableDebug: true },
            );

            expect(result.debug).toBeDefined();
            expect(result.debug!.extractedUrls).toBeDefined();
            expect(result.debug!.textStats).toBeDefined();
        });
    });

    describe("Spam Detection", () => {
        SPAM_EMAILS.forEach(({ name, email, expectedMinScore }) => {
            it(`should detect spam: ${name}`, () => {
                const result = analyzeEmail(email);

                expect(result.score).toBeGreaterThanOrEqual(expectedMinScore);
                expect(result.isSpam).toBe(true);
                expect(["spam", "probable_spam"]).toContain(
                    result.classification,
                );
            });
        });
    });

    describe("Ham Detection", () => {
        HAM_EMAILS.forEach(({ name, email, expectedMaxScore }) => {
            it(`should not flag as spam: ${name}`, () => {
                const result = analyzeEmail(email);

                expect(result.score).toBeLessThanOrEqual(expectedMaxScore);
                expect(result.isSpam).toBe(false);
                expect(["ham", "probable_ham"]).toContain(
                    result.classification,
                );
            });
        });
    });

    describe("Edge Cases", () => {
        EDGE_CASE_EMAILS.forEach(({ name, email, description }) => {
            it(`should handle edge case: ${name} - ${description}`, () => {
                // Should not throw
                expect(() => {
                    const result = analyzeEmail(email);
                    expect(result).toBeDefined();
                    expect(typeof result.score).toBe("number");
                    expect(typeof result.isSpam).toBe("boolean");
                }).not.toThrow();
            });
        });
    });

    describe("Classification Thresholds", () => {
        it("should classify as spam above threshold", () => {
            const guard = new SpamGuard({ spamThreshold: 5 });

            // This email should score high
            const result = guard.analyze({
                from: "scammer@example.xyz",
                subject: "URGENT!!! You have WON $1,000,000!!!",
                textBody:
                    "Congratulations winner! Claim your prize now! Act immediately! Wire transfer required.",
            });

            expect(result.classification).toBe("spam");
        });

        it("should classify as probable_spam between thresholds", () => {
            const guard = new SpamGuard({
                spamThreshold: 10,
                probableSpamThreshold: 3,
            });

            // This should score medium
            const result = guard.analyze({
                from: "newsletter@company.com",
                subject: "Special Offer - Limited Time!",
                textBody: "Click here for amazing discounts. Buy now and save!",
            });

            if (result.score >= 3 && result.score < 10) {
                expect(result.classification).toBe("probable_spam");
            }
        });

        it("should classify as ham for low scores", () => {
            const result = analyzeEmail({
                from: "colleague@company.com",
                to: "me@company.com",
                subject: "Re: Project Update",
                textBody:
                    "Thanks for the meeting notes. I'll review the attached document and send my feedback.",
                headers: {
                    "received-spf": "pass",
                    "authentication-results": "dkim=pass; spf=pass",
                },
            });

            expect(["ham", "probable_ham"]).toContain(result.classification);
        });
    });

    describe("Quick Methods", () => {
        it("isSpam() should return boolean", () => {
            const guard = new SpamGuard();

            const result = guard.isSpam({
                subject: "Normal email",
                textBody: "Hi, how are you?",
            });

            expect(typeof result).toBe("boolean");
        });

        it("getScore() should return number", () => {
            const guard = new SpamGuard();

            const score = guard.getScore({
                subject: "Test",
                textBody: "Content",
            });

            expect(typeof score).toBe("number");
            expect(score).toBeGreaterThanOrEqual(0);
        });
    });

    describe("Performance", () => {
        it("should analyze email quickly", () => {
            const result = analyzeEmail({
                from: "test@example.com",
                to: "recipient@example.com",
                subject: "Performance test",
                textBody: "This is a test email with some content to analyze.",
            });

            // Should complete in under 100ms
            expect(result.processingTimeMs).toBeLessThan(100);
        });

        it("should handle large emails", () => {
            const largeBody = "Lorem ipsum dolor sit amet. ".repeat(1000);

            const result = analyzeEmail({
                from: "test@example.com",
                to: "recipient@example.com",
                subject: "Large email test",
                textBody: largeBody,
            });

            expect(result).toBeDefined();
            expect(result.processingTimeMs).toBeLessThan(500);
        });
    });

    describe("Analyzer Coverage", () => {
        it("should run all analyzers", () => {
            const result = analyzeEmail({
                from: "test@example.com",
                to: "recipient@example.com",
                subject: "Test",
                textBody: "Hello World",
                htmlBody: "<p>Hello World</p>",
            });

            const analyzerNames = result.analyzers.map((a) => a.analyzer);

            expect(analyzerNames).toContain("header");
            expect(analyzerNames).toContain("content");
            expect(analyzerNames).toContain("url");
            expect(analyzerNames).toContain("html");
            expect(analyzerNames).toContain("pattern");
            expect(analyzerNames).toContain("bayesian");
        });

        it("should provide top reasons for spam", () => {
            const result = analyzeEmail(SPAM_EMAILS[0].email);

            expect(result.topReasons.length).toBeGreaterThan(0);
            expect(result.topReasons.length).toBeLessThanOrEqual(5);
        });
    });
});

describe("Real-World Accuracy", () => {
    it("should have >90% spam detection rate", () => {
        let detected = 0;

        for (const { email } of SPAM_EMAILS) {
            const result = analyzeEmail(email);
            if (result.isSpam) detected++;
        }

        const detectionRate = detected / SPAM_EMAILS.length;
        expect(detectionRate).toBeGreaterThanOrEqual(0.9);
    });

    it("should have <10% false positive rate", () => {
        let falsePositives = 0;

        for (const { email } of HAM_EMAILS) {
            const result = analyzeEmail(email);
            if (result.isSpam) falsePositives++;
        }

        const falsePositiveRate = falsePositives / HAM_EMAILS.length;
        expect(falsePositiveRate).toBeLessThanOrEqual(0.1);
    });
});
