// ============================================================================
// HTML Analyzer
// Analyzes HTML content for spam indicators
// ============================================================================

import type {
    AnalyzerResult,
    RuleMatch,
    AnalysisRule,
    ParsedEmail,
} from "../types";
import { extractTextFromHtml } from "../utils/text";

const HTML_RULES: AnalysisRule[] = [
    {
        name: "HIDDEN_TEXT",
        description: "Hidden text detected (CSS tricks)",
        score: 2.5,
        category: "html",
    },
    {
        name: "TINY_FONT",
        description: "Very small font size detected",
        score: 2.0,
        category: "html",
    },
    {
        name: "INVISIBLE_INK",
        description: "Text color matches background",
        score: 2.5,
        category: "html",
    },
    {
        name: "EXCESSIVE_IMAGES",
        description: "Email contains many images",
        score: 0.8,
        category: "html",
    },
    {
        name: "IMAGE_ONLY",
        description: "Email contains only images (no text)",
        score: 2.0,
        category: "html",
    },
    {
        name: "REMOTE_IMAGES",
        description: "Email loads remote images (tracking)",
        score: 0.5,
        category: "html",
    },
    {
        name: "SUSPICIOUS_FORM",
        description: "Email contains form elements",
        score: 1.5,
        category: "html",
    },
    {
        name: "JAVASCRIPT_PRESENT",
        description: "Email contains JavaScript",
        score: 2.0,
        category: "html",
    },
    {
        name: "IFRAME_PRESENT",
        description: "Email contains iframe",
        score: 2.5,
        category: "html",
    },
    {
        name: "OBJECT_EMBED",
        description: "Email contains object/embed tags",
        score: 2.0,
        category: "html",
    },
    {
        name: "STYLE_MANIPULATION",
        description: "Suspicious style manipulation",
        score: 1.5,
        category: "html",
    },
    {
        name: "TRACKING_PIXEL",
        description: "Tracking pixel detected",
        score: 0.8,
        category: "html",
    },
    {
        name: "BASE64_IMAGE",
        description: "Embedded base64 image",
        score: 0.3,
        category: "html",
    },
    {
        name: "MALFORMED_HTML",
        description: "Malformed HTML structure",
        score: 0.5,
        category: "html",
    },
    {
        name: "COMMENT_STUFFING",
        description: "Excessive HTML comments",
        score: 1.0,
        category: "html",
    },
    {
        name: "TABLE_SPAM_LAYOUT",
        description: "Spam-typical table layout",
        score: 0.5,
        category: "html",
    },
];

export function analyzeHtml(email: ParsedEmail): AnalyzerResult {
    const matches: RuleMatch[] = [];
    let totalScore = 0;

    const html = email.htmlBody;

    // No HTML to analyze
    if (!html || html.trim().length === 0) {
        return {
            analyzer: "html",
            score: 0,
            maxScore: HTML_RULES.reduce((sum, r) => sum + r.score, 0),
            matches: [],
            metadata: { hasHtml: false },
        };
    }

    const lowerHtml = html.toLowerCase();

    // Check for hidden text (display:none, visibility:hidden)
    const hiddenPatterns = [
        /display\s*:\s*none/gi,
        /visibility\s*:\s*hidden/gi,
        /opacity\s*:\s*0(?:[^.]|$)/gi,
        /height\s*:\s*0/gi,
        /font-size\s*:\s*0/gi,
    ];

    for (const pattern of hiddenPatterns) {
        if (pattern.test(html)) {
            const rule = HTML_RULES.find((r) => r.name === "HIDDEN_TEXT")!;
            if (!matches.find((m) => m.rule.name === "HIDDEN_TEXT")) {
                matches.push({
                    rule,
                    matched: true,
                    details: "CSS hiding technique detected",
                });
                totalScore += rule.score;
            }
        }
    }

    // Check for tiny font
    const tinyFontPattern = /font-size\s*:\s*([0-4]|0?\.[0-9]+)\s*(px|pt|em)/gi;
    if (tinyFontPattern.test(html)) {
        const rule = HTML_RULES.find((r) => r.name === "TINY_FONT")!;
        matches.push({
            rule,
            matched: true,
            details: "Very small font size detected",
        });
        totalScore += rule.score;
    }

    // Check for invisible ink (color matching background)
    const colorPatterns = [
        /color\s*:\s*(#fff(?:fff)?|white|#f{6})\s*;[^}]*background[^}]*:\s*\1/gi,
        /background[^}]*:\s*(#fff(?:fff)?|white|#f{6})[^}]*color\s*:\s*\1/gi,
        /color\s*:\s*(#000(?:000)?|black|#0{6})\s*;[^}]*background[^}]*:\s*\1/gi,
    ];

    for (const pattern of colorPatterns) {
        if (pattern.test(html)) {
            const rule = HTML_RULES.find((r) => r.name === "INVISIBLE_INK")!;
            if (!matches.find((m) => m.rule.name === "INVISIBLE_INK")) {
                matches.push({
                    rule,
                    matched: true,
                    details: "Text color matches background",
                });
                totalScore += rule.score;
            }
        }
    }

    // Count images
    const imgTags = (html.match(/<img\b/gi) || []).length;

    if (imgTags > 10) {
        const rule = HTML_RULES.find((r) => r.name === "EXCESSIVE_IMAGES")!;
        matches.push({
            rule,
            matched: true,
            details: `${imgTags} images found`,
        });
        totalScore += rule.score;
    }

    // Check for image-only email
    const textContent = extractTextFromHtml(html).trim();
    if (imgTags > 0 && textContent.length < 50) {
        const rule = HTML_RULES.find((r) => r.name === "IMAGE_ONLY")!;
        matches.push({
            rule,
            matched: true,
            details: "Email appears to be image-only",
        });
        totalScore += rule.score;
    }

    // Check for remote images (tracking)
    const remoteImgPattern = /<img[^>]*src\s*=\s*["']https?:\/\//gi;
    const remoteImages = (html.match(remoteImgPattern) || []).length;
    if (remoteImages > 0) {
        const rule = HTML_RULES.find((r) => r.name === "REMOTE_IMAGES")!;
        matches.push({
            rule,
            matched: true,
            details: `${remoteImages} remote images`,
        });
        totalScore += rule.score;
    }

    // Check for tracking pixel (1x1 image)
    const trackingPixelPatterns = [
        /<img[^>]*(?:width|height)\s*=\s*["']?1["']?[^>]*(?:width|height)\s*=\s*["']?1["']?/gi,
        /<img[^>]*style\s*=\s*["'][^"']*(?:width|height)\s*:\s*1px[^"']*["']/gi,
    ];

    for (const pattern of trackingPixelPatterns) {
        if (pattern.test(html)) {
            const rule = HTML_RULES.find((r) => r.name === "TRACKING_PIXEL")!;
            if (!matches.find((m) => m.rule.name === "TRACKING_PIXEL")) {
                matches.push({
                    rule,
                    matched: true,
                    details: "1x1 tracking pixel detected",
                });
                totalScore += rule.score;
            }
        }
    }

    // Check for base64 images
    const base64ImgPattern = /<img[^>]*src\s*=\s*["']data:image/gi;
    if (base64ImgPattern.test(html)) {
        const rule = HTML_RULES.find((r) => r.name === "BASE64_IMAGE")!;
        matches.push({ rule, matched: true, details: "Base64 embedded image" });
        totalScore += rule.score;
    }

    // Check for form elements
    if (/<form\b/i.test(html)) {
        const rule = HTML_RULES.find((r) => r.name === "SUSPICIOUS_FORM")!;
        matches.push({ rule, matched: true, details: "Form element in email" });
        totalScore += rule.score;
    }

    // Check for JavaScript
    const jsPatterns = [
        /<script\b/i,
        /\bon\w+\s*=/i, // onclick, onload, etc.
        /javascript\s*:/i,
    ];

    for (const pattern of jsPatterns) {
        if (pattern.test(html)) {
            const rule = HTML_RULES.find(
                (r) => r.name === "JAVASCRIPT_PRESENT",
            )!;
            if (!matches.find((m) => m.rule.name === "JAVASCRIPT_PRESENT")) {
                matches.push({
                    rule,
                    matched: true,
                    details: "JavaScript detected in email",
                });
                totalScore += rule.score;
            }
        }
    }

    // Check for iframe
    if (/<iframe\b/i.test(html)) {
        const rule = HTML_RULES.find((r) => r.name === "IFRAME_PRESENT")!;
        matches.push({ rule, matched: true, details: "Iframe in email" });
        totalScore += rule.score;
    }

    // Check for object/embed
    if (/<(?:object|embed)\b/i.test(html)) {
        const rule = HTML_RULES.find((r) => r.name === "OBJECT_EMBED")!;
        matches.push({
            rule,
            matched: true,
            details: "Object/embed tag in email",
        });
        totalScore += rule.score;
    }

    // Check for excessive comments (comment stuffing)
    const comments = html.match(/<!--[\s\S]*?-->/g) || [];
    const totalCommentLength = comments.reduce((sum, c) => sum + c.length, 0);

    if (comments.length > 10 || totalCommentLength > 1000) {
        const rule = HTML_RULES.find((r) => r.name === "COMMENT_STUFFING")!;
        matches.push({
            rule,
            matched: true,
            details: `${comments.length} comments, ${totalCommentLength} chars`,
        });
        totalScore += rule.score;
    }

    // Check for spam-typical table layout
    const nestedTables = (html.match(/<table\b/gi) || []).length;
    if (nestedTables > 5) {
        const rule = HTML_RULES.find((r) => r.name === "TABLE_SPAM_LAYOUT")!;
        matches.push({
            rule,
            matched: true,
            details: `${nestedTables} nested tables`,
        });
        totalScore += rule.score;
    }

    // Check for malformed HTML
    const openTags = (html.match(/<[a-z][a-z0-9]*\b/gi) || []).length;
    const closeTags = (html.match(/<\/[a-z][a-z0-9]*>/gi) || []).length;

    if (openTags > 0 && Math.abs(openTags - closeTags) / openTags > 0.3) {
        const rule = HTML_RULES.find((r) => r.name === "MALFORMED_HTML")!;
        matches.push({
            rule,
            matched: true,
            details: `Open: ${openTags}, Close: ${closeTags}`,
        });
        totalScore += rule.score;
    }

    return {
        analyzer: "html",
        score: totalScore,
        maxScore: HTML_RULES.reduce((sum, r) => sum + r.score, 0),
        matches,
        metadata: {
            hasHtml: true,
            imageCount: imgTags,
            remoteImageCount: remoteImages,
            tableCount: nestedTables,
            textLength: textContent.length,
        },
    };
}
