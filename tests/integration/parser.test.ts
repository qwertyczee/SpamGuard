// ============================================================================
// Email Parser Tests
// ============================================================================

import { describe, it, expect } from "bun:test";
import { parseEmail, parseEmailAddress } from "../../src/parser/email";

describe("Email Parser", () => {
    describe("parseEmailAddress", () => {
        it("should parse simple email address", () => {
            const result = parseEmailAddress("user@example.com");
            expect(result).not.toBeNull();
            expect(result!.address).toBe("user@example.com");
            expect(result!.localPart).toBe("user");
            expect(result!.domain).toBe("example.com");
            expect(result!.name).toBeNull();
        });

        it("should parse email with display name", () => {
            const result = parseEmailAddress("John Doe <john@example.com>");
            expect(result).not.toBeNull();
            expect(result!.address).toBe("john@example.com");
            expect(result!.name).toBe("John Doe");
        });

        it("should parse email with quoted display name", () => {
            const result = parseEmailAddress('"John Doe" <john@example.com>');
            expect(result).not.toBeNull();
            expect(result!.address).toBe("john@example.com");
            expect(result!.name).toBe("John Doe");
        });

        it("should handle empty string", () => {
            const result = parseEmailAddress("");
            expect(result).toBeNull();
        });

        it("should handle invalid format", () => {
            const result = parseEmailAddress("not an email");
            expect(result).toBeNull();
        });

        it("should normalize domain to lowercase", () => {
            const result = parseEmailAddress("User@EXAMPLE.COM");
            expect(result!.domain).toBe("example.com");
        });
    });

    describe("parseEmail - Structured Input", () => {
        it("should parse basic structured email", () => {
            const result = parseEmail({
                from: "sender@example.com",
                to: "recipient@example.com",
                subject: "Test Subject",
                textBody: "Hello World",
            });

            expect(result.from!.address).toBe("sender@example.com");
            expect(result.to[0].address).toBe("recipient@example.com");
            expect(result.subject).toBe("Test Subject");
            expect(result.textBody).toBe("Hello World");
        });

        it("should parse multiple recipients", () => {
            const result = parseEmail({
                from: "sender@example.com",
                to: ["user1@example.com", "user2@example.com"],
                subject: "Test",
            });

            expect(result.to).toHaveLength(2);
            expect(result.to[0].address).toBe("user1@example.com");
            expect(result.to[1].address).toBe("user2@example.com");
        });

        it("should handle HTML body", () => {
            const result = parseEmail({
                from: "sender@example.com",
                to: "recipient@example.com",
                subject: "HTML Email",
                htmlBody: "<html><body><p>Hello</p></body></html>",
            });

            expect(result.htmlBody).toContain("<html>");
        });

        it("should parse headers", () => {
            const result = parseEmail({
                from: "sender@example.com",
                to: "recipient@example.com",
                subject: "Test",
                headers: {
                    "x-custom-header": "custom value",
                    "received-spf": "pass",
                },
            });

            expect(result.headers.get("x-custom-header")).toContain(
                "custom value",
            );
            expect(result.headers.get("received-spf")).toContain("pass");
        });

        it("should parse reply-to and return-path", () => {
            const result = parseEmail({
                from: "sender@example.com",
                to: "recipient@example.com",
                subject: "Test",
                replyTo: "reply@example.com",
                returnPath: "<bounce@example.com>",
            });

            expect(result.replyTo!.address).toBe("reply@example.com");
            expect(result.returnPath).toBe("<bounce@example.com>");
        });

        it("should handle empty input", () => {
            const result = parseEmail({});

            expect(result.from).toBeNull();
            expect(result.to).toHaveLength(0);
            expect(result.subject).toBe("");
            expect(result.textBody).toBe("");
        });
    });

    describe("parseEmail - Raw MIME Input", () => {
        it("should parse simple raw email", () => {
            const raw = `From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 10 Jan 2025 12:00:00 +0000
Message-ID: <test123@example.com>

This is the body of the email.`;

            const result = parseEmail({ raw });

            expect(result.from!.address).toBe("sender@example.com");
            expect(result.to[0].address).toBe("recipient@example.com");
            expect(result.subject).toBe("Test Email");
            expect(result.messageId).toBe("<test123@example.com>");
            expect(result.textBody).toContain("This is the body");
        });

        it("should handle multiline headers", () => {
            const raw = `From: sender@example.com
To: recipient@example.com
Subject: This is a very long subject line
 that continues on the next line
 and even further

Body content here.`;

            const result = parseEmail({ raw });

            expect(result.subject).toContain("very long subject");
            expect(result.subject).toContain("continues");
        });

        it("should parse Received headers", () => {
            const raw = `From: sender@example.com
To: recipient@example.com
Received: from mail.example.com by mx.recipient.com with SMTP; Mon, 10 Jan 2025 12:00:00 +0000
Subject: Test

Body`;

            const result = parseEmail({ raw });

            expect(result.receivedChain).toHaveLength(1);
            expect(result.receivedChain[0].from).toBe("mail.example.com");
            expect(result.receivedChain[0].by).toBe("mx.recipient.com");
        });
    });
});
