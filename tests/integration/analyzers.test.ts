// ============================================================================
// Analyzer Tests
// ============================================================================

import { describe, it, expect } from "bun:test";
import { analyzeHeaders } from "../../src/analyzers/header";
import { analyzeContent } from "../../src/analyzers/content";
import { analyzeUrls } from "../../src/analyzers/url";
import { analyzeHtml } from "../../src/analyzers/html";
import { analyzePatterns } from "../../src/analyzers/pattern";
import { analyzeBayesian } from "../../src/analyzers/bayesian";
import { parseEmail } from "../../src/parser/email";

describe("Header Analyzer", () => {
    it("should detect SPF failure", () => {
        const email = parseEmail({
            from: "sender@example.com",
            to: "recipient@example.com",
            subject: "Test",
            headers: {
                "received-spf": "fail (domain example.com)",
            },
        });

        const result = analyzeHeaders(email);
        const spfMatch = result.matches.find((m) => m.rule.name === "SPF_FAIL");
        expect(spfMatch).toBeDefined();
        expect(result.score).toBeGreaterThan(0);
    });

    it("should detect missing Message-ID", () => {
        const email = parseEmail({
            from: "sender@example.com",
            to: "recipient@example.com",
            subject: "Test",
        });

        const result = analyzeHeaders(email);
        const match = result.matches.find(
            (m) => m.rule.name === "MISSING_MESSAGE_ID",
        );
        expect(match).toBeDefined();
    });

    it("should detect From/Reply-To mismatch", () => {
        const email = parseEmail({
            from: "sender@company.com",
            to: "recipient@example.com",
            subject: "Test",
            replyTo: "different@other-domain.com",
        });

        const result = analyzeHeaders(email);
        const match = result.matches.find(
            (m) => m.rule.name === "FROM_REPLY_TO_MISMATCH",
        );
        expect(match).toBeDefined();
    });

    it("should detect disposable email", () => {
        const email = parseEmail({
            from: "user@tempmail.com",
            to: "recipient@example.com",
            subject: "Test",
        });

        const result = analyzeHeaders(email);
        const match = result.matches.find(
            (m) => m.rule.name === "DISPOSABLE_EMAIL",
        );
        expect(match).toBeDefined();
    });

    it("should detect freemail provider", () => {
        const email = parseEmail({
            from: "user@gmail.com",
            to: "recipient@example.com",
            subject: "Test",
        });

        const result = analyzeHeaders(email);
        const match = result.matches.find(
            (m) => m.rule.name === "FREEMAIL_FROM",
        );
        expect(match).toBeDefined();
    });

    it("should have low score for legitimate headers", () => {
        const email = parseEmail({
            from: "user@company.com",
            to: "recipient@example.com",
            subject: "Test",
            messageId: "<123@company.com>",
            date: new Date().toISOString(),
            headers: {
                "received-spf": "pass",
                "dkim-signature": "v=1; a=rsa-sha256; d=company.com",
                "authentication-results": "dkim=pass; spf=pass; dmarc=pass",
            },
        });

        const result = analyzeHeaders(email);
        expect(result.score).toBeLessThan(3);
    });
});

describe("Content Analyzer", () => {
    it("should detect spam phrases", () => {
        const email = parseEmail({
            from: "spammer@example.com",
            to: "victim@example.com",
            subject: "URGENT: Act Now!",
            textBody:
                "Congratulations winner! You have won $1,000,000. Act now to claim your prize!",
        });

        const result = analyzeContent(email);
        expect(result.score).toBeGreaterThan(3);
        expect(result.matches.length).toBeGreaterThan(0);
    });

    it("should detect all caps subject", () => {
        const email = parseEmail({
            from: "sender@example.com",
            to: "recipient@example.com",
            subject: "THIS IS ALL CAPS SUBJECT LINE",
            textBody: "Normal body content",
        });

        const result = analyzeContent(email);
        const match = result.matches.find(
            (m) => m.rule.name === "SUBJECT_ALL_CAPS",
        );
        expect(match).toBeDefined();
    });

    it("should reduce score for ham phrases", () => {
        const email = parseEmail({
            from: "colleague@company.com",
            to: "recipient@company.com",
            subject: "Re: Project meeting",
            textBody:
                "Thanks for the meeting summary. As discussed, I've attached the report. Regards, John",
        });

        const result = analyzeContent(email);
        const hamMatches = result.matches.filter(
            (m) => m.rule.name === "HAM_PHRASE_MATCH",
        );
        expect(hamMatches.length).toBeGreaterThan(0);
    });

    it("should detect empty body", () => {
        const email = parseEmail({
            from: "sender@example.com",
            to: "recipient@example.com",
            subject: "Empty email",
            textBody: "",
        });

        const result = analyzeContent(email);
        const match = result.matches.find((m) => m.rule.name === "EMPTY_BODY");
        expect(match).toBeDefined();
    });

    it("should detect multiple exclamation marks", () => {
        const email = parseEmail({
            from: "sender@example.com",
            to: "recipient@example.com",
            subject: "Test!!!",
            textBody:
                "Amazing offer!!! Don't miss out!!! Act now!!! Limited time!!!",
        });

        const result = analyzeContent(email);
        const match = result.matches.find(
            (m) => m.rule.name === "MULTIPLE_EXCLAMATIONS",
        );
        expect(match).toBeDefined();
    });
});

describe("URL Analyzer", () => {
    it("should detect IP address URLs", () => {
        const email = parseEmail({
            from: "sender@example.com",
            to: "recipient@example.com",
            subject: "Test",
            textBody: "Click here: http://192.168.1.1/login",
        });

        const result = analyzeUrls(email);
        const match = result.matches.find(
            (m) => m.rule.name === "IP_ADDRESS_URL",
        );
        expect(match).toBeDefined();
    });

    it("should detect suspicious TLDs", () => {
        const email = parseEmail({
            from: "sender@example.com",
            to: "recipient@example.com",
            subject: "Test",
            textBody: "Visit http://free-stuff.xyz or http://malware.tk",
        });

        const result = analyzeUrls(email);
        const match = result.matches.find(
            (m) => m.rule.name === "SUSPICIOUS_TLD",
        );
        expect(match).toBeDefined();
    });

    it("should detect URL shorteners", () => {
        const email = parseEmail({
            from: "sender@example.com",
            to: "recipient@example.com",
            subject: "Test",
            textBody: "Check this out: https://bit.ly/abc123",
        });

        const result = analyzeUrls(email);
        const match = result.matches.find(
            (m) => m.rule.name === "URL_SHORTENER",
        );
        expect(match).toBeDefined();
    });

    it("should detect mismatched link text", () => {
        const email = parseEmail({
            from: "sender@example.com",
            to: "recipient@example.com",
            subject: "Test",
            htmlBody:
                '<a href="http://malicious.com/steal">https://google.com</a>',
        });

        const result = analyzeUrls(email);
        const match = result.matches.find(
            (m) => m.rule.name === "MISMATCHED_LINK_TEXT",
        );
        expect(match).toBeDefined();
    });

    it("should not flag legitimate domains", () => {
        const email = parseEmail({
            from: "sender@example.com",
            to: "recipient@example.com",
            subject: "Test",
            textBody: "Visit https://google.com and https://github.com",
        });

        const result = analyzeUrls(email);
        expect(result.score).toBeLessThan(2);
    });
});

describe("HTML Analyzer", () => {
    it("should detect hidden text", () => {
        const email = parseEmail({
            from: "sender@example.com",
            to: "recipient@example.com",
            subject: "Test",
            htmlBody:
                '<div style="display:none">Hidden spam content</div><p>Visible content</p>',
        });

        const result = analyzeHtml(email);
        const match = result.matches.find((m) => m.rule.name === "HIDDEN_TEXT");
        expect(match).toBeDefined();
    });

    it("should detect tracking pixels", () => {
        const email = parseEmail({
            from: "sender@example.com",
            to: "recipient@example.com",
            subject: "Test",
            htmlBody:
                '<p>Hello</p><img src="http://tracker.com/pixel.gif" width="1" height="1">',
        });

        const result = analyzeHtml(email);
        const match = result.matches.find(
            (m) => m.rule.name === "TRACKING_PIXEL",
        );
        expect(match).toBeDefined();
    });

    it("should detect JavaScript", () => {
        const email = parseEmail({
            from: "sender@example.com",
            to: "recipient@example.com",
            subject: "Test",
            htmlBody: '<script>alert("xss")</script><p>Hello</p>',
        });

        const result = analyzeHtml(email);
        const match = result.matches.find(
            (m) => m.rule.name === "JAVASCRIPT_PRESENT",
        );
        expect(match).toBeDefined();
    });

    it("should detect forms", () => {
        const email = parseEmail({
            from: "sender@example.com",
            to: "recipient@example.com",
            subject: "Test",
            htmlBody:
                '<form action="http://evil.com/steal"><input name="password"></form>',
        });

        const result = analyzeHtml(email);
        const match = result.matches.find(
            (m) => m.rule.name === "SUSPICIOUS_FORM",
        );
        expect(match).toBeDefined();
    });

    it("should detect iframe", () => {
        const email = parseEmail({
            from: "sender@example.com",
            to: "recipient@example.com",
            subject: "Test",
            htmlBody: '<iframe src="http://malicious.com"></iframe>',
        });

        const result = analyzeHtml(email);
        const match = result.matches.find(
            (m) => m.rule.name === "IFRAME_PRESENT",
        );
        expect(match).toBeDefined();
    });

    it("should handle no HTML", () => {
        const email = parseEmail({
            from: "sender@example.com",
            to: "recipient@example.com",
            subject: "Test",
            textBody: "Plain text only",
        });

        const result = analyzeHtml(email);
        expect(result.score).toBe(0);
    });
});

describe("Pattern Analyzer", () => {
    it("should detect invisible characters", () => {
        const email = parseEmail({
            from: "sender@example.com",
            to: "recipient@example.com",
            subject: "Test",
            textBody: "Hello\u200BWorld", // Zero-width space
        });

        const result = analyzePatterns(email);
        const match = result.matches.find(
            (m) => m.rule.name === "INVISIBLE_CHARS",
        );
        expect(match).toBeDefined();
    });

    it("should detect mixed scripts", () => {
        const email = parseEmail({
            from: "sender@example.com",
            to: "recipient@example.com",
            subject: "Test",
            textBody: "Hello Привет mixed scripts",
        });

        const result = analyzePatterns(email);
        const match = result.matches.find(
            (m) => m.rule.name === "MIXED_SCRIPTS",
        );
        expect(match).toBeDefined();
    });

    it("should detect multiple urgency phrases", () => {
        const email = parseEmail({
            from: "sender@example.com",
            to: "recipient@example.com",
            subject: "URGENT",
            textBody:
                "Act now! Urgent! Immediate action required! Limited time! ASAP!",
        });

        const result = analyzePatterns(email);
        const match = result.matches.find(
            (m) => m.rule.name === "MULTIPLE_URGENCY",
        );
        expect(match).toBeDefined();
    });

    it("should detect suspicious greetings", () => {
        const email = parseEmail({
            from: "sender@example.com",
            to: "recipient@example.com",
            subject: "Important",
            textBody: "Dear Friend,\n\nI am writing to inform you...",
        });

        const result = analyzePatterns(email);
        expect(result.score).toBeGreaterThan(0);
    });
});

describe("Bayesian Analyzer", () => {
    it("should classify spam-heavy content", () => {
        const email = parseEmail({
            from: "sender@example.com",
            to: "recipient@example.com",
            subject: "Test",
            textBody:
                "viagra cialis pharmacy prescription pills medication cheap discount free offer",
        });

        const result = analyzeBayesian(email);
        expect(result.metadata.spamProbability).toBeGreaterThan(0.5);
    });

    it("should classify ham-heavy content", () => {
        const email = parseEmail({
            from: "sender@example.com",
            to: "recipient@example.com",
            subject: "Meeting",
            textBody:
                "Hi, regarding our meeting schedule, attached is the project report. Thanks for your feedback on the documentation.",
        });

        const result = analyzeBayesian(email);
        expect(result.metadata.spamProbability).toBeLessThan(0.5);
    });

    it("should handle empty content", () => {
        const email = parseEmail({
            from: "sender@example.com",
            to: "recipient@example.com",
            subject: "",
            textBody: "",
        });

        const result = analyzeBayesian(email);
        expect(result.metadata.tokenCount).toBe(0);
        expect(result.metadata.spamProbability).toBe(0.5);
    });
});
