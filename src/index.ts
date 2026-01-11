// ============================================================================
// SpamGuard API
// Hono-based REST API for spam detection
// ============================================================================

import { Hono } from "hono";
import { cors } from "hono/cors";
import { prettyJSON } from "hono/pretty-json";
import { SpamGuard, analyzeEmail } from "./engine";
import type { EmailInput, SpamGuardConfig } from "./types";

// Create app
const app = new Hono();

// Middleware
app.use("*", cors());
app.use("*", prettyJSON());

// Health check
app.get("/", (c) => {
    return c.json({
        name: "SpamGuard",
        version: "1.0.0",
        description: "Intelligent spam detection service",
        endpoints: {
            "POST /analyze": "Full spam analysis",
            "POST /check": "Quick spam check (true/false)",
            "POST /score": "Get spam score only",
            "POST /batch": "Analyze multiple emails",
            "GET /health": "Health check",
            "GET /config": "Get default configuration",
        },
    });
});

// Health check endpoint
app.get("/health", (c) => {
    return c.json({
        status: "healthy",
        timestamp: new Date().toISOString(),
    });
});

// Get default configuration
app.get("/config", (c) => {
    const guard = new SpamGuard();
    return c.json(guard.getConfig());
});

// Full analysis endpoint
app.post("/analyze", async (c) => {
    try {
        const body = await c.req.json();

        // Validate input
        if (!body || typeof body !== "object") {
            return c.json({ error: "Invalid request body" }, 400);
        }

        const email: EmailInput = {
            from: body.from,
            to: body.to,
            subject: body.subject,
            messageId: body.messageId || body.message_id,
            date: body.date,
            replyTo: body.replyTo || body.reply_to,
            returnPath: body.returnPath || body.return_path,
            receivedSpf: body.receivedSpf || body.received_spf,
            dkimSignature: body.dkimSignature || body.dkim_signature,
            authenticationResults:
                body.authenticationResults || body.authentication_results,
            headers: body.headers,
            textBody: body.textBody || body.text_body || body.text || body.body,
            htmlBody: body.htmlBody || body.html_body || body.html,
            clientIp: body.clientIp || body.client_ip,
            helo: body.helo,
            raw: body.raw,
        };

        // Get config overrides
        const config: Partial<SpamGuardConfig> = {};
        if (body.config) {
            if (typeof body.config.spamThreshold === "number") {
                config.spamThreshold = body.config.spamThreshold;
            }
            if (typeof body.config.probableSpamThreshold === "number") {
                config.probableSpamThreshold =
                    body.config.probableSpamThreshold;
            }
            if (typeof body.config.enableDebug === "boolean") {
                config.enableDebug = body.config.enableDebug;
            }
        }

        // Also check top-level debug flag
        if (body.debug === true) {
            config.enableDebug = true;
        }

        const result = analyzeEmail(email, config);

        return c.json(result);
    } catch (error) {
        console.error("Analysis error:", error);
        return c.json(
            {
                error: "Analysis failed",
                message:
                    error instanceof Error ? error.message : "Unknown error",
            },
            500,
        );
    }
});

// Quick check endpoint (just returns true/false)
app.post("/check", async (c) => {
    try {
        const body = await c.req.json();

        const email: EmailInput = {
            from: body.from,
            to: body.to,
            subject: body.subject,
            textBody: body.textBody || body.text_body || body.text || body.body,
            htmlBody: body.htmlBody || body.html_body || body.html,
            headers: body.headers,
            raw: body.raw,
        };

        const guard = new SpamGuard();
        const isSpam = guard.isSpam(email);

        return c.json({ isSpam });
    } catch (error) {
        console.error("Check error:", error);
        return c.json(
            {
                error: "Check failed",
                message:
                    error instanceof Error ? error.message : "Unknown error",
            },
            500,
        );
    }
});

// Score only endpoint
app.post("/score", async (c) => {
    try {
        const body = await c.req.json();

        const email: EmailInput = {
            from: body.from,
            to: body.to,
            subject: body.subject,
            textBody: body.textBody || body.text_body || body.text || body.body,
            htmlBody: body.htmlBody || body.html_body || body.html,
            headers: body.headers,
            raw: body.raw,
        };

        const result = analyzeEmail(email);

        return c.json({
            score: result.score,
            threshold: result.threshold,
            classification: result.classification,
        });
    } catch (error) {
        console.error("Score error:", error);
        return c.json(
            {
                error: "Scoring failed",
                message:
                    error instanceof Error ? error.message : "Unknown error",
            },
            500,
        );
    }
});

// Batch analysis endpoint
app.post("/batch", async (c) => {
    try {
        const body = await c.req.json();

        if (!Array.isArray(body.emails)) {
            return c.json({ error: "emails array required" }, 400);
        }

        if (body.emails.length > 100) {
            return c.json({ error: "Maximum 100 emails per batch" }, 400);
        }

        const guard = new SpamGuard(body.config || {});

        const results = body.emails.map((email: any, index: number) => {
            try {
                const input: EmailInput = {
                    from: email.from,
                    to: email.to,
                    subject: email.subject,
                    textBody:
                        email.textBody ||
                        email.text_body ||
                        email.text ||
                        email.body,
                    htmlBody: email.htmlBody || email.html_body || email.html,
                    headers: email.headers,
                    raw: email.raw,
                };

                const result = guard.analyze(input);
                return {
                    index,
                    success: true,
                    ...result,
                };
            } catch (error) {
                return {
                    index,
                    success: false,
                    error:
                        error instanceof Error
                            ? error.message
                            : "Analysis failed",
                };
            }
        });

        const summary = {
            total: results.length,
            spam: results.filter((r: any) => r.success && r.isSpam).length,
            ham: results.filter((r: any) => r.success && !r.isSpam).length,
            errors: results.filter((r: any) => !r.success).length,
        };

        return c.json({ summary, results });
    } catch (error) {
        console.error("Batch error:", error);
        return c.json(
            {
                error: "Batch analysis failed",
                message:
                    error instanceof Error ? error.message : "Unknown error",
            },
            500,
        );
    }
});

// Analyze raw MIME email
app.post("/analyze/raw", async (c) => {
    try {
        const contentType = c.req.header("content-type") || "";

        let raw: string;
        if (
            contentType.includes("text/plain") ||
            contentType.includes("message/rfc822")
        ) {
            raw = await c.req.text();
        } else {
            const body = await c.req.json();
            raw = body.raw || body.email || body.message;
        }

        if (!raw) {
            return c.json({ error: "Raw email content required" }, 400);
        }

        const result = analyzeEmail({ raw });

        return c.json(result);
    } catch (error) {
        console.error("Raw analysis error:", error);
        return c.json(
            {
                error: "Raw analysis failed",
                message:
                    error instanceof Error ? error.message : "Unknown error",
            },
            500,
        );
    }
});

// Export for Cloudflare Workers
export default app;
