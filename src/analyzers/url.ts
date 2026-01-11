// ============================================================================
// URL Analyzer
// Analyzes URLs in email for spam/phishing indicators
// ============================================================================

import type {
    AnalyzerResult,
    RuleMatch,
    AnalysisRule,
    ParsedEmail,
    UrlInfo,
} from "../types";
import {
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
    SPAM_DOMAIN_PATTERNS,
    SUSPICIOUS_PATH_PATTERNS,
    IP_URL_PATTERN,
    LEGITIMATE_DOMAINS,
    getRootDomain,
    getTld,
} from "../data/url-blacklist";
import { extractUrls, extractTextFromHtml } from "../utils/text";

const URL_RULES: AnalysisRule[] = [
    {
        name: "IP_ADDRESS_URL",
        description: "URL uses IP address instead of domain",
        score: 2.5,
        category: "url",
    },
    {
        name: "SUSPICIOUS_TLD",
        description: "URL uses suspicious TLD",
        score: 1.5,
        category: "url",
    },
    {
        name: "URL_SHORTENER",
        description: "URL uses shortening service",
        score: 1.0,
        category: "url",
    },
    {
        name: "PHISHING_DOMAIN",
        description: "Domain matches phishing pattern",
        score: 2.5,
        category: "url",
    },
    {
        name: "SUSPICIOUS_PATH",
        description: "URL path contains suspicious pattern",
        score: 1.5,
        category: "url",
    },
    {
        name: "MANY_URLS",
        description: "Email contains many URLs",
        score: 1.0,
        category: "url",
    },
    {
        name: "URL_WITH_PORT",
        description: "URL contains non-standard port",
        score: 1.5,
        category: "url",
    },
    {
        name: "ENCODED_URL",
        description: "URL contains excessive encoding",
        score: 1.2,
        category: "url",
    },
    {
        name: "MISMATCHED_LINK_TEXT",
        description: "Link text differs from actual URL",
        score: 2.0,
        category: "url",
    },
    {
        name: "EXECUTABLE_LINK",
        description: "Link points to executable file",
        score: 2.5,
        category: "url",
    },
    {
        name: "LONG_SUBDOMAIN",
        description: "URL has unusually long subdomain",
        score: 1.0,
        category: "url",
    },
    {
        name: "MANY_SUBDOMAINS",
        description: "URL has many subdomain levels",
        score: 1.0,
        category: "url",
    },
];

/**
 * Parse URL into components for analysis
 */
function parseUrl(url: string): UrlInfo | null {
    try {
        // Handle URLs without protocol
        let fullUrl = url;
        if (!url.match(/^https?:\/\//i)) {
            fullUrl = "http://" + url;
        }

        const parsed = new URL(fullUrl);
        const domain = parsed.hostname.toLowerCase();
        const tld = getTld(domain);

        return {
            original: url,
            protocol: parsed.protocol,
            domain,
            tld,
            path: parsed.pathname,
            query: parsed.search,
            isIpAddress: IP_URL_PATTERN.test(fullUrl),
            isSuspiciousTld: SUSPICIOUS_TLDS.has(tld),
            hasPortNumber:
                parsed.port !== "" &&
                parsed.port !== "80" &&
                parsed.port !== "443",
            isShortener:
                URL_SHORTENERS.has(domain) ||
                URL_SHORTENERS.has(getRootDomain(domain)),
            encodedChars: /%[0-9a-f]{2}/i.test(url),
        };
    } catch {
        return null;
    }
}

/**
 * Extract mismatched links from HTML (where link text differs from href)
 */
function findMismatchedLinks(
    html: string,
): Array<{ text: string; href: string }> {
    const mismatched: Array<{ text: string; href: string }> = [];

    // Find all anchor tags
    const linkPattern = /<a[^>]*href=["']([^"']+)["'][^>]*>([^<]+)<\/a>/gi;
    let match;

    while ((match = linkPattern.exec(html)) !== null) {
        const href = match[1];
        const text = match[2].trim();

        // Check if link text looks like a URL but differs from href
        if (
            text.match(/^https?:\/\//i) ||
            text.match(/^www\./i) ||
            text.includes(".com")
        ) {
            try {
                const textDomain = text
                    .replace(/^https?:\/\//i, "")
                    .split("/")[0]
                    .toLowerCase();
                const hrefParsed = new URL(
                    href.startsWith("http") ? href : "http://" + href,
                );
                const hrefDomain = hrefParsed.hostname.toLowerCase();

                if (
                    textDomain !== hrefDomain &&
                    !textDomain.endsWith(hrefDomain)
                ) {
                    mismatched.push({ text, href });
                }
            } catch {
                // Invalid URL in text, might be suspicious
                mismatched.push({ text, href });
            }
        }
    }

    return mismatched;
}

export function analyzeUrls(email: ParsedEmail): AnalyzerResult {
    const matches: RuleMatch[] = [];
    let totalScore = 0;

    // Extract URLs from both text and HTML
    const textUrls = extractUrls(email.textBody);
    const htmlUrls = extractUrls(email.htmlBody);
    const htmlText = extractTextFromHtml(email.htmlBody);
    const htmlTextUrls = extractUrls(htmlText);

    // Deduplicate
    const allUrls = [...new Set([...textUrls, ...htmlUrls, ...htmlTextUrls])];
    const extractedUrls = allUrls.slice(0, 50); // Limit for performance

    // Parse all URLs
    const parsedUrls = extractedUrls
        .map(parseUrl)
        .filter((u): u is UrlInfo => u !== null);

    // Check for many URLs
    if (parsedUrls.length > 10) {
        const rule = URL_RULES.find((r) => r.name === "MANY_URLS")!;
        matches.push({
            rule,
            matched: true,
            details: `${parsedUrls.length} URLs found`,
        });
        totalScore += rule.score;
    }

    // Analyze each URL
    const checkedDomains = new Set<string>();

    for (const urlInfo of parsedUrls) {
        const rootDomain = getRootDomain(urlInfo.domain);

        // Skip if we already checked this domain
        if (checkedDomains.has(rootDomain)) continue;
        checkedDomains.add(rootDomain);

        // Skip legitimate domains
        if (LEGITIMATE_DOMAINS.has(rootDomain)) continue;

        // IP address URL
        if (urlInfo.isIpAddress) {
            const rule = URL_RULES.find((r) => r.name === "IP_ADDRESS_URL")!;
            matches.push({
                rule,
                matched: true,
                details: urlInfo.original,
                evidence: [urlInfo.original],
            });
            totalScore += rule.score;
        }

        // Suspicious TLD
        if (urlInfo.isSuspiciousTld) {
            const rule = URL_RULES.find((r) => r.name === "SUSPICIOUS_TLD")!;
            matches.push({
                rule,
                matched: true,
                details: `.${urlInfo.tld}`,
                evidence: [urlInfo.original],
            });
            totalScore += rule.score;
        }

        // URL shortener
        if (urlInfo.isShortener) {
            const rule = URL_RULES.find((r) => r.name === "URL_SHORTENER")!;
            matches.push({
                rule,
                matched: true,
                details: urlInfo.domain,
                evidence: [urlInfo.original],
            });
            totalScore += rule.score;
        }

        // Non-standard port
        if (urlInfo.hasPortNumber) {
            const rule = URL_RULES.find((r) => r.name === "URL_WITH_PORT")!;
            matches.push({
                rule,
                matched: true,
                details: urlInfo.original,
                evidence: [urlInfo.original],
            });
            totalScore += rule.score;
        }

        // Encoded characters
        if (urlInfo.encodedChars) {
            const encodedCount = (
                urlInfo.original.match(/%[0-9a-f]{2}/gi) || []
            ).length;
            if (encodedCount > 3) {
                const rule = URL_RULES.find((r) => r.name === "ENCODED_URL")!;
                matches.push({
                    rule,
                    matched: true,
                    details: `${encodedCount} encoded chars`,
                    evidence: [urlInfo.original],
                });
                totalScore += rule.score;
            }
        }

        // Check domain patterns
        for (const pattern of SPAM_DOMAIN_PATTERNS) {
            if (pattern.pattern.test(urlInfo.domain)) {
                matches.push({
                    rule: {
                        name: `PHISHING_DOMAIN_${pattern.name}`,
                        description: `Domain matches phishing pattern: ${pattern.name}`,
                        score: pattern.score,
                        category: "url",
                    },
                    matched: true,
                    details: urlInfo.domain,
                    evidence: [urlInfo.original],
                });
                totalScore += pattern.score;
                break; // One match per domain
            }
        }

        // Check path patterns
        for (const pattern of SUSPICIOUS_PATH_PATTERNS) {
            if (pattern.pattern.test(urlInfo.path + urlInfo.query)) {
                matches.push({
                    rule: {
                        name: `SUSPICIOUS_PATH_${pattern.name}`,
                        description: `URL path matches suspicious pattern: ${pattern.name}`,
                        score: pattern.score,
                        category: "url",
                    },
                    matched: true,
                    details: urlInfo.path,
                    evidence: [urlInfo.original],
                });
                totalScore += pattern.score;
                break; // One match per URL
            }
        }

        // Check subdomain analysis
        const subdomains = urlInfo.domain.split(".");
        if (subdomains.length > 4) {
            const rule = URL_RULES.find((r) => r.name === "MANY_SUBDOMAINS")!;
            matches.push({
                rule,
                matched: true,
                details: urlInfo.domain,
                evidence: [urlInfo.original],
            });
            totalScore += rule.score;
        }

        // Long subdomain
        for (const sub of subdomains.slice(0, -2)) {
            if (sub.length > 20) {
                const rule = URL_RULES.find(
                    (r) => r.name === "LONG_SUBDOMAIN",
                )!;
                matches.push({
                    rule,
                    matched: true,
                    details: sub,
                    evidence: [urlInfo.original],
                });
                totalScore += rule.score;
                break;
            }
        }
    }

    // Check for mismatched links in HTML
    if (email.htmlBody) {
        const mismatchedLinks = findMismatchedLinks(email.htmlBody);

        for (const mismatch of mismatchedLinks) {
            const rule = URL_RULES.find(
                (r) => r.name === "MISMATCHED_LINK_TEXT",
            )!;
            matches.push({
                rule,
                matched: true,
                details: `Text: "${mismatch.text}" -> "${mismatch.href}"`,
                evidence: [mismatch.text, mismatch.href],
            });
            totalScore += rule.score;
        }
    }

    return {
        analyzer: "url",
        score: totalScore,
        maxScore: URL_RULES.reduce((sum, r) => sum + r.score, 0) * 3, // Multiple URLs possible
        matches,
        metadata: {
            urlCount: parsedUrls.length,
            uniqueDomains: checkedDomains.size,
            shortenerCount: parsedUrls.filter((u) => u.isShortener).length,
            ipAddressCount: parsedUrls.filter((u) => u.isIpAddress).length,
        },
    };
}
