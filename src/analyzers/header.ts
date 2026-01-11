// ============================================================================
// Header Analyzer
// Analyzes email headers for spam indicators
// ============================================================================

import type {
    AnalyzerResult,
    RuleMatch,
    AnalysisRule,
    ParsedEmail,
} from "../types";

const HEADER_RULES: AnalysisRule[] = [
    // Authentication failures
    {
        name: "SPF_FAIL",
        description: "SPF check failed",
        score: 2.5,
        category: "authentication",
    },
    {
        name: "SPF_SOFTFAIL",
        description: "SPF check soft failed",
        score: 1.5,
        category: "authentication",
    },
    {
        name: "SPF_NONE",
        description: "No SPF record",
        score: 0.1,
        category: "authentication",
    },
    {
        name: "DKIM_FAIL",
        description: "DKIM signature invalid",
        score: 2.0,
        category: "authentication",
    },
    {
        name: "DKIM_NONE",
        description: "No DKIM signature",
        score: 0.0,
        category: "authentication",
    },
    {
        name: "DMARC_FAIL",
        description: "DMARC policy failed",
        score: 2.5,
        category: "authentication",
    },

    // Header anomalies
    {
        name: "MISSING_FROM",
        description: "Missing From header",
        score: 2.0,
        category: "header",
    },
    {
        name: "MISSING_DATE",
        description: "Missing Date header",
        score: 0.1,
        category: "header",
    },
    {
        name: "MISSING_MESSAGE_ID",
        description: "Missing Message-ID header",
        score: 0.1,
        category: "header",
    },

    {
        name: "INVALID_MESSAGE_ID",
        description: "Invalid Message-ID format",
        score: 1.0,
        category: "header",
    },
    {
        name: "FORGED_RECEIVED",
        description: "Forged or suspicious Received header",
        score: 2.0,
        category: "header",
    },
    {
        name: "TOO_MANY_RECEIVED",
        description: "Unusually many Received headers",
        score: 1.0,
        category: "header",
    },
    {
        name: "FROM_REPLY_TO_MISMATCH",
        description: "From and Reply-To domains differ",
        score: 1.5,
        category: "header",
    },
    {
        name: "FROM_RETURN_PATH_MISMATCH",
        description: "From and Return-Path differ significantly",
        score: 1.0,
        category: "header",
    },
    {
        name: "SUSPICIOUS_MAILER",
        description: "Suspicious X-Mailer header",
        score: 1.0,
        category: "header",
    },
    {
        name: "FUTURE_DATE",
        description: "Email date is in the future",
        score: 1.5,
        category: "header",
    },
    {
        name: "VERY_OLD_DATE",
        description: "Email date is very old",
        score: 1.0,
        category: "header",
    },
    {
        name: "FREEMAIL_FROM",
        description: "From address is from free email provider",
        score: 0.3,
        category: "header",
    },
    {
        name: "DISPOSABLE_EMAIL",
        description: "From address is disposable email",
        score: 2.0,
        category: "header",
    },
    {
        name: "TO_NO_RECIPIENT",
        description: "No valid To recipient",
        score: 1.5,
        category: "header",
    },
    {
        name: "TO_UNDISCLOSED",
        description: "Undisclosed recipients",
        score: 0.8,
        category: "header",
    },
    {
        name: "HIGH_PRIORITY_SPAM",
        description: "High priority header often used in spam",
        score: 0.5,
        category: "header",
    },
];

const FREEMAIL_DOMAINS = new Set([
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "aol.com",
    "mail.com",
    "protonmail.com",
    "icloud.com",
    "zoho.com",
    "yandex.com",
    "gmx.com",
    "gmx.net",
    "live.com",
    "msn.com",
    "me.com",
]);

const DISPOSABLE_DOMAINS = new Set([
    "tempmail.com",
    "guerrillamail.com",
    "10minutemail.com",
    "mailinator.com",
    "throwaway.email",
    "temp-mail.org",
    "fakeinbox.com",
    "trashmail.com",
    "getnada.com",
    "maildrop.cc",
    "dispostable.com",
    "yopmail.com",
    "sharklasers.com",
    "guerrillamail.info",
    "grr.la",
    "spam4.me",
]);

const SUSPICIOUS_MAILERS = [
    /mass\s*mail/i,
    /bulk\s*mail/i,
    /email\s*blast/i,
    /newsletter/i,
    /phpmailer/i,
    /swiftmailer/i,
];

export function analyzeHeaders(email: ParsedEmail): AnalyzerResult {
    const matches: RuleMatch[] = [];
    let totalScore = 0;

    // Check authentication results
    const authResults = email.headers.get("authentication-results")?.[0] || "";
    const receivedSpf = email.headers.get("received-spf")?.[0] || "";

    // SPF checks
    if (
        receivedSpf.toLowerCase().includes("fail") &&
        !receivedSpf.toLowerCase().includes("softfail")
    ) {
        const rule = HEADER_RULES.find((r) => r.name === "SPF_FAIL")!;
        matches.push({
            rule,
            matched: true,
            details: "SPF authentication failed",
        });
        totalScore += rule.score;
    } else if (receivedSpf.toLowerCase().includes("softfail")) {
        const rule = HEADER_RULES.find((r) => r.name === "SPF_SOFTFAIL")!;
        matches.push({ rule, matched: true, details: "SPF soft fail" });
        totalScore += rule.score;
    } else if (receivedSpf.toLowerCase().includes("none") || !receivedSpf) {
        const rule = HEADER_RULES.find((r) => r.name === "SPF_NONE")!;
        matches.push({ rule, matched: true, details: "No SPF record found" });
        totalScore += rule.score;
    }

    // DKIM checks
    const dkimSignature = email.headers.get("dkim-signature")?.[0];
    if (authResults.toLowerCase().includes("dkim=fail")) {
        const rule = HEADER_RULES.find((r) => r.name === "DKIM_FAIL")!;
        matches.push({
            rule,
            matched: true,
            details: "DKIM signature validation failed",
        });
        totalScore += rule.score;
    } else if (!dkimSignature) {
        const rule = HEADER_RULES.find((r) => r.name === "DKIM_NONE")!;
        matches.push({
            rule,
            matched: true,
            details: "No DKIM signature present",
        });
        totalScore += rule.score;
    }

    // DMARC checks
    if (authResults.toLowerCase().includes("dmarc=fail")) {
        const rule = HEADER_RULES.find((r) => r.name === "DMARC_FAIL")!;
        matches.push({ rule, matched: true, details: "DMARC policy failed" });
        totalScore += rule.score;
    }

    // Check for missing From
    if (!email.from) {
        const rule = HEADER_RULES.find((r) => r.name === "MISSING_FROM")!;
        matches.push({ rule, matched: true, details: "No From header" });
        totalScore += rule.score;
    }

    // Check for missing Date
    if (!email.date) {
        const rule = HEADER_RULES.find((r) => r.name === "MISSING_DATE")!;
        matches.push({ rule, matched: true, details: "No Date header" });
        totalScore += rule.score;
    } else {
        const now = new Date();
        const emailDate = email.date;

        // Future date
        if (emailDate.getTime() > now.getTime() + 86400000) {
            // More than 1 day in future
            const rule = HEADER_RULES.find((r) => r.name === "FUTURE_DATE")!;
            matches.push({
                rule,
                matched: true,
                details: `Date is in the future: ${emailDate.toISOString()}`,
            });
            totalScore += rule.score;
        }

        // Very old date (more than 1 year)
        const oneYearAgo = new Date(now.getTime() - 365 * 86400000);
        if (emailDate < oneYearAgo) {
            const rule = HEADER_RULES.find((r) => r.name === "VERY_OLD_DATE")!;
            matches.push({
                rule,
                matched: true,
                details: `Date is very old: ${emailDate.toISOString()}`,
            });
            totalScore += rule.score;
        }
    }

    // Check Message-ID
    if (!email.messageId) {
        const rule = HEADER_RULES.find((r) => r.name === "MISSING_MESSAGE_ID")!;
        matches.push({ rule, matched: true, details: "No Message-ID header" });
        totalScore += rule.score;
    } else {
        // Validate Message-ID format (should be <something@something>)
        const validMessageId = /^<[^@]+@[^>]+>$/.test(email.messageId);
        if (!validMessageId) {
            const rule = HEADER_RULES.find(
                (r) => r.name === "INVALID_MESSAGE_ID",
            )!;
            matches.push({
                rule,
                matched: true,
                details: `Invalid Message-ID format: ${email.messageId}`,
            });
            totalScore += rule.score;
        }
    }

    // Check Received headers
    const receivedHeaders = email.receivedChain;
    if (receivedHeaders.length > 15) {
        const rule = HEADER_RULES.find((r) => r.name === "TOO_MANY_RECEIVED")!;
        matches.push({
            rule,
            matched: true,
            details: `${receivedHeaders.length} Received headers`,
        });
        totalScore += rule.score;
    }

    // Check for forged Received headers (internal IPs in external hops)
    for (const received of receivedHeaders) {
        if (received.from) {
            const hasInternalIp =
                /\b(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b/.test(
                    received.from,
                );
            const hasPublicDomain = /\.(com|net|org|edu|gov)/.test(
                received.from,
            );

            if (hasInternalIp && hasPublicDomain) {
                const rule = HEADER_RULES.find(
                    (r) => r.name === "FORGED_RECEIVED",
                )!;
                matches.push({
                    rule,
                    matched: true,
                    details: `Suspicious Received header: ${received.from}`,
                });
                totalScore += rule.score;
                break;
            }
        }
    }

    // Check From vs Reply-To mismatch
    if (email.from && email.replyTo) {
        if (email.from.domain !== email.replyTo.domain) {
            const rule = HEADER_RULES.find(
                (r) => r.name === "FROM_REPLY_TO_MISMATCH",
            )!;
            matches.push({
                rule,
                matched: true,
                details: `From: ${email.from.domain}, Reply-To: ${email.replyTo.domain}`,
            });
            totalScore += rule.score;
        }
    }

    // Check From vs Return-Path mismatch
    if (email.from && email.returnPath) {
        const returnPathMatch = email.returnPath.match(/@([^>]+)/);
        const returnPathDomain = returnPathMatch?.[1]?.toLowerCase();

        if (returnPathDomain && email.from.domain !== returnPathDomain) {
            const rule = HEADER_RULES.find(
                (r) => r.name === "FROM_RETURN_PATH_MISMATCH",
            )!;
            matches.push({
                rule,
                matched: true,
                details: `From: ${email.from.domain}, Return-Path: ${returnPathDomain}`,
            });
            totalScore += rule.score;
        }
    }

    // Check X-Mailer
    const xMailer = email.headers.get("x-mailer")?.[0] || "";
    for (const pattern of SUSPICIOUS_MAILERS) {
        if (pattern.test(xMailer)) {
            const rule = HEADER_RULES.find(
                (r) => r.name === "SUSPICIOUS_MAILER",
            )!;
            matches.push({
                rule,
                matched: true,
                details: `X-Mailer: ${xMailer}`,
            });
            totalScore += rule.score;
            break;
        }
    }

    // Check for freemail/disposable email
    if (email.from) {
        const fromDomain = email.from.domain.toLowerCase();

        if (DISPOSABLE_DOMAINS.has(fromDomain)) {
            const rule = HEADER_RULES.find(
                (r) => r.name === "DISPOSABLE_EMAIL",
            )!;
            matches.push({
                rule,
                matched: true,
                details: `Disposable email: ${fromDomain}`,
            });
            totalScore += rule.score;
        } else if (FREEMAIL_DOMAINS.has(fromDomain)) {
            const rule = HEADER_RULES.find((r) => r.name === "FREEMAIL_FROM")!;
            matches.push({
                rule,
                matched: true,
                details: `Freemail provider: ${fromDomain}`,
            });
            totalScore += rule.score;
        }
    }

    // Check To header
    if (email.to.length === 0) {
        const rule = HEADER_RULES.find((r) => r.name === "TO_NO_RECIPIENT")!;
        matches.push({ rule, matched: true, details: "No valid To recipient" });
        totalScore += rule.score;
    } else {
        const toHeader = email.headers.get("to")?.[0] || "";
        if (toHeader.toLowerCase().includes("undisclosed")) {
            const rule = HEADER_RULES.find((r) => r.name === "TO_UNDISCLOSED")!;
            matches.push({
                rule,
                matched: true,
                details: "Undisclosed recipients",
            });
            totalScore += rule.score;
        }
    }

    // Check priority headers
    const priority =
        email.headers.get("x-priority")?.[0] ||
        email.headers.get("importance")?.[0] ||
        "";
    if (priority === "1" || priority.toLowerCase() === "high") {
        const rule = HEADER_RULES.find((r) => r.name === "HIGH_PRIORITY_SPAM")!;
        matches.push({
            rule,
            matched: true,
            details: "High priority flag set",
        });
        totalScore += rule.score;
    }

    return {
        analyzer: "header",
        score: totalScore,
        maxScore: HEADER_RULES.reduce((sum, r) => sum + r.score, 0),
        matches,
        metadata: {
            fromDomain: email.from?.domain,
            hasSpf: !!receivedSpf,
            hasDkim: !!dkimSignature,
            receivedCount: receivedHeaders.length,
        },
    };
}
