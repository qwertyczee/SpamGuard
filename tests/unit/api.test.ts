// ============================================================================
// API Integration Tests
// ============================================================================

import { describe, it, expect } from "bun:test";
import app from "../../src/index";
import { SPAM_EMAILS, HAM_EMAILS } from "../fixtures/emails.test";

// Helper to make requests
async function request(
    method: string,
    path: string,
    body?: any,
): Promise<{ status: number; json: any }> {
    const req = new Request(`http://localhost${path}`, {
        method,
        headers: body ? { "Content-Type": "application/json" } : {},
        body: body ? JSON.stringify(body) : undefined,
    });

    const res = await app.fetch(req);
    const json = await res.json();

    return { status: res.status, json };
}

describe("API Endpoints", () => {
    describe("GET /", () => {
        it("should return API info", async () => {
            const { status, json } = await request("GET", "/");

            expect(status).toBe(200);
            expect(json.name).toBe("SpamGuard");
            expect(json.version).toBe("1.0.0");
            expect(json.endpoints).toBeDefined();
        });
    });

    describe("GET /health", () => {
        it("should return health status", async () => {
            const { status, json } = await request("GET", "/health");

            expect(status).toBe(200);
            expect(json.status).toBe("healthy");
            expect(json.timestamp).toBeDefined();
        });
    });

    describe("GET /config", () => {
        it("should return default config", async () => {
            const { status, json } = await request("GET", "/config");

            expect(status).toBe(200);
            expect(json.spamThreshold).toBe(3.5);
            expect(json.probableSpamThreshold).toBe(2.0);
        });
    });

    describe("POST /analyze", () => {
        it("should analyze email and return full result", async () => {
            const { status, json } = await request("POST", "/analyze", {
                from: "test@example.com",
                to: "recipient@example.com",
                subject: "Test Email",
                textBody: "This is a test email.",
            });

            expect(status).toBe(200);
            expect(json.isSpam).toBeDefined();
            expect(json.score).toBeDefined();
            expect(json.classification).toBeDefined();
            expect(json.analyzers).toBeDefined();
        });

        it("should detect spam correctly", async () => {
            const spamEmail = SPAM_EMAILS[0].email;
            const { status, json } = await request(
                "POST",
                "/analyze",
                spamEmail,
            );

            expect(status).toBe(200);
            expect(json.isSpam).toBe(true);
        });

        it("should pass ham correctly", async () => {
            const hamEmail = HAM_EMAILS[0].email;
            const { status, json } = await request(
                "POST",
                "/analyze",
                hamEmail,
            );

            expect(status).toBe(200);
            expect(json.isSpam).toBe(false);
        });

        it("should accept snake_case field names", async () => {
            const { status, json } = await request("POST", "/analyze", {
                from: "test@example.com",
                to: "recipient@example.com",
                subject: "Test",
                text_body: "Hello World",
                html_body: "<p>Hello</p>",
            });

            expect(status).toBe(200);
            expect(json.isSpam).toBeDefined();
        });

        it("should accept config overrides", async () => {
            const { status, json } = await request("POST", "/analyze", {
                from: "test@example.com",
                subject: "Test",
                textBody: "Hello",
                config: {
                    spamThreshold: 100, // Very high threshold
                },
            });

            expect(status).toBe(200);
            expect(json.threshold).toBe(100);
            expect(json.isSpam).toBe(false);
        });

        it("should include debug info when requested", async () => {
            const { status, json } = await request("POST", "/analyze", {
                from: "test@example.com",
                subject: "Test",
                textBody: "Hello https://example.com",
                debug: true,
            });

            expect(status).toBe(200);
            expect(json.debug).toBeDefined();
            expect(json.debug.extractedUrls).toBeDefined();
        });

        it("should handle invalid body", async () => {
            const req = new Request("http://localhost/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: "invalid json",
            });

            const res = await app.fetch(req);
            expect(res.status).toBe(500);
        });
    });

    describe("POST /check", () => {
        it("should return simple boolean result", async () => {
            const { status, json } = await request("POST", "/check", {
                from: "test@example.com",
                subject: "Hello",
                textBody: "Just a friendly message.",
            });

            expect(status).toBe(200);
            expect(typeof json.isSpam).toBe("boolean");
            expect(Object.keys(json)).toHaveLength(1);
        });

        it("should detect spam", async () => {
            const { json } = await request(
                "POST",
                "/check",
                SPAM_EMAILS[0].email,
            );
            expect(json.isSpam).toBe(true);
        });

        it("should pass ham", async () => {
            const { json } = await request(
                "POST",
                "/check",
                HAM_EMAILS[0].email,
            );
            expect(json.isSpam).toBe(false);
        });
    });

    describe("POST /score", () => {
        it("should return score and classification", async () => {
            const { status, json } = await request("POST", "/score", {
                from: "test@example.com",
                subject: "Test",
                textBody: "Content",
            });

            expect(status).toBe(200);
            expect(typeof json.score).toBe("number");
            expect(json.threshold).toBeDefined();
            expect(json.classification).toBeDefined();
        });
    });

    describe("POST /batch", () => {
        it("should analyze multiple emails", async () => {
            const { status, json } = await request("POST", "/batch", {
                emails: [
                    {
                        from: "a@example.com",
                        subject: "Test 1",
                        textBody: "Hello",
                    },
                    {
                        from: "b@example.com",
                        subject: "Test 2",
                        textBody: "World",
                    },
                ],
            });

            expect(status).toBe(200);
            expect(json.summary).toBeDefined();
            expect(json.summary.total).toBe(2);
            expect(json.results).toHaveLength(2);
        });

        it("should return summary statistics", async () => {
            const { json } = await request("POST", "/batch", {
                emails: [HAM_EMAILS[0].email, SPAM_EMAILS[0].email],
            });

            expect(json.summary.total).toBe(2);
            expect(json.summary.spam).toBe(1);
            expect(json.summary.ham).toBe(1);
        });

        it("should reject more than 100 emails", async () => {
            const emails = Array(101).fill({
                subject: "Test",
                textBody: "Content",
            });

            const { status, json } = await request("POST", "/batch", {
                emails,
            });

            expect(status).toBe(400);
            expect(json.error).toContain("100");
        });

        it("should require emails array", async () => {
            const { status, json } = await request("POST", "/batch", {});

            expect(status).toBe(400);
            expect(json.error).toContain("emails");
        });

        it("should handle errors in individual emails", async () => {
            const { json } = await request("POST", "/batch", {
                emails: [
                    { subject: "Valid", textBody: "Content" },
                    null, // Invalid
                ],
            });

            expect(json.summary.errors).toBeGreaterThanOrEqual(0);
        });
    });

    describe("POST /analyze/raw", () => {
        it("should analyze raw MIME email", async () => {
            const rawEmail = `From: sender@example.com
To: recipient@example.com
Subject: Test Raw Email

This is the body of the raw email.`;

            const { status, json } = await request("POST", "/analyze/raw", {
                raw: rawEmail,
            });

            expect(status).toBe(200);
            expect(json.isSpam).toBeDefined();
        });

        it("should accept text/plain content type", async () => {
            const rawEmail = `From: sender@example.com
To: recipient@example.com
Subject: Plain Text Test

Body content here.`;

            const req = new Request("http://localhost/analyze/raw", {
                method: "POST",
                headers: { "Content-Type": "text/plain" },
                body: rawEmail,
            });

            const res = await app.fetch(req);
            const json = await res.json();

            expect(res.status).toBe(200);
            expect(json.isSpam).toBeDefined();
        });

        it("should require raw content", async () => {
            const { status, json } = await request("POST", "/analyze/raw", {});

            expect(status).toBe(400);
            expect(json.error).toContain("required");
        });
    });
});

describe("API Error Handling", () => {
    it("should return 404 for unknown routes", async () => {
        const req = new Request("http://localhost/unknown");
        const res = await app.fetch(req);

        expect(res.status).toBe(404);
    });

    it("should handle malformed JSON gracefully", async () => {
        const req = new Request("http://localhost/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: "{ invalid json }",
        });

        const res = await app.fetch(req);
        expect(res.status).toBe(500);
    });
});
