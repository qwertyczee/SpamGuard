// ============================================================================
// Text Utility Tests
// ============================================================================

import { describe, it, expect } from "bun:test";
import {
    calculateTextStats,
    extractUrls,
    extractEmails,
    detectLanguage,
    normalizeText,
    extractTextFromHtml,
    decodeHtmlEntities,
    stringSimilarity,
    hasInvisibleChars,
    hasMixedScripts,
    getDomainFromEmail,
    isValidEmail,
    calculateEntropy,
} from "../../src/utils/text";

describe("Text Utilities", () => {
    describe("calculateTextStats", () => {
        it("should calculate basic stats", () => {
            const stats = calculateTextStats("Hello World");
            expect(stats.wordCount).toBe(2);
            expect(stats.charCount).toBe(11);
        });

        it("should calculate uppercase ratio", () => {
            const stats = calculateTextStats("HELLO world");
            expect(stats.uppercaseRatio).toBeCloseTo(0.5, 1);
        });

        it("should calculate digit ratio", () => {
            const stats = calculateTextStats("abc123");
            expect(stats.digitRatio).toBeCloseTo(0.5, 1);
        });

        it("should handle empty string", () => {
            const stats = calculateTextStats("");
            expect(stats.wordCount).toBe(0);
            expect(stats.charCount).toBe(0);
            expect(stats.avgWordLength).toBe(0);
        });

        it("should calculate word length stats", () => {
            const stats = calculateTextStats("a bb ccc dddd eeeee");
            expect(stats.avgWordLength).toBeCloseTo(3, 1);
            expect(stats.shortWordRatio).toBeGreaterThan(0);
        });
    });

    describe("extractUrls", () => {
        it("should extract HTTP URLs", () => {
            const urls = extractUrls("Visit http://example.com for more info");
            expect(urls).toContain("http://example.com");
        });

        it("should extract HTTPS URLs", () => {
            const urls = extractUrls(
                "Secure site: https://secure.example.com/path",
            );
            expect(urls).toContain("https://secure.example.com/path");
        });

        it("should extract multiple URLs", () => {
            const urls = extractUrls("Check http://a.com and https://b.com");
            expect(urls).toHaveLength(2);
        });

        it("should handle URLs with query strings", () => {
            const urls = extractUrls(
                "Link: https://example.com/page?id=123&name=test",
            );
            expect(urls[0]).toContain("id=123");
        });

        it("should clean trailing punctuation", () => {
            const urls = extractUrls("Visit http://example.com.");
            expect(urls[0]).toBe("http://example.com");
        });

        it("should return empty array for no URLs", () => {
            const urls = extractUrls("No URLs here");
            expect(urls).toHaveLength(0);
        });
    });

    describe("extractEmails", () => {
        it("should extract simple email", () => {
            const emails = extractEmails("Contact us at info@example.com");
            expect(emails).toContain("info@example.com");
        });

        it("should extract multiple emails", () => {
            const emails = extractEmails("Email a@b.com or c@d.com");
            expect(emails).toHaveLength(2);
        });

        it("should handle emails with subdomains", () => {
            const emails = extractEmails("user@mail.subdomain.example.com");
            expect(emails[0]).toContain("subdomain");
        });

        it("should return empty array for no emails", () => {
            const emails = extractEmails("No emails here");
            expect(emails).toHaveLength(0);
        });
    });

    describe("detectLanguage", () => {
        it("should detect Latin text", () => {
            expect(detectLanguage("Hello World")).toBe("latin");
        });

        it("should detect Cyrillic text", () => {
            expect(detectLanguage("Привет мир")).toBe("cyrillic");
        });

        it("should detect Chinese text", () => {
            expect(detectLanguage("你好世界")).toBe("chinese");
        });

        it("should detect Arabic text", () => {
            expect(detectLanguage("مرحبا بالعالم")).toBe("arabic");
        });

        it("should return unknown for empty/numeric", () => {
            expect(detectLanguage("12345")).toBe("unknown");
        });
    });

    describe("normalizeText", () => {
        it("should lowercase text", () => {
            expect(normalizeText("HELLO")).toBe("hello");
        });

        it("should collapse whitespace", () => {
            expect(normalizeText("hello    world")).toBe("hello world");
        });

        it("should trim text", () => {
            expect(normalizeText("  hello  ")).toBe("hello");
        });
    });

    describe("extractTextFromHtml", () => {
        it("should remove HTML tags", () => {
            const text = extractTextFromHtml("<p>Hello <b>World</b></p>");
            expect(text).toContain("Hello");
            expect(text).toContain("World");
            expect(text).not.toContain("<");
        });

        it("should remove script tags", () => {
            const text = extractTextFromHtml(
                '<p>Hello</p><script>alert("x")</script>',
            );
            expect(text).not.toContain("alert");
        });

        it("should remove style tags", () => {
            const text = extractTextFromHtml(
                "<style>.x{color:red}</style><p>Hello</p>",
            );
            expect(text).not.toContain("color");
        });

        it("should decode HTML entities", () => {
            const text = extractTextFromHtml("<p>Hello &amp; World</p>");
            expect(text).toContain("Hello & World");
        });

        it("should handle empty HTML", () => {
            expect(extractTextFromHtml("")).toBe("");
        });
    });

    describe("decodeHtmlEntities", () => {
        it("should decode named entities", () => {
            expect(decodeHtmlEntities("&amp;")).toBe("&");
            expect(decodeHtmlEntities("&lt;")).toBe("<");
            expect(decodeHtmlEntities("&gt;")).toBe(">");
            expect(decodeHtmlEntities("&quot;")).toBe('"');
        });

        it("should decode numeric entities", () => {
            expect(decodeHtmlEntities("&#65;")).toBe("A");
            expect(decodeHtmlEntities("&#x41;")).toBe("A");
        });

        it("should handle multiple entities", () => {
            expect(decodeHtmlEntities("&lt;script&gt;")).toBe("<script>");
        });
    });

    describe("stringSimilarity", () => {
        it("should return 1 for identical strings", () => {
            expect(stringSimilarity("hello", "hello")).toBe(1);
        });

        it("should return 0 for completely different strings", () => {
            expect(stringSimilarity("abc", "xyz")).toBeLessThan(0.5);
        });

        it("should handle empty strings", () => {
            expect(stringSimilarity("", "")).toBe(1);
            expect(stringSimilarity("hello", "")).toBe(0);
        });

        it("should return high similarity for similar strings", () => {
            expect(stringSimilarity("hello", "hallo")).toBeGreaterThan(0.7);
        });
    });

    describe("hasInvisibleChars", () => {
        it("should detect zero-width space", () => {
            expect(hasInvisibleChars("hello\u200Bworld")).toBe(true);
        });

        it("should detect zero-width joiner", () => {
            expect(hasInvisibleChars("hello\u200Dworld")).toBe(true);
        });

        it("should return false for normal text", () => {
            expect(hasInvisibleChars("Hello World")).toBe(false);
        });
    });

    describe("hasMixedScripts", () => {
        it("should detect Latin + Cyrillic mix", () => {
            expect(hasMixedScripts("Hello Привет")).toBe(true);
        });

        it("should return false for single script", () => {
            expect(hasMixedScripts("Hello World")).toBe(false);
            expect(hasMixedScripts("Привет мир")).toBe(false);
        });
    });

    describe("getDomainFromEmail", () => {
        it("should extract domain", () => {
            expect(getDomainFromEmail("user@example.com")).toBe("example.com");
        });

        it("should handle subdomain", () => {
            expect(getDomainFromEmail("user@mail.example.com")).toBe(
                "mail.example.com",
            );
        });

        it("should handle invalid format", () => {
            expect(getDomainFromEmail("invalid")).toBe("");
        });
    });

    describe("isValidEmail", () => {
        it("should validate correct emails", () => {
            expect(isValidEmail("user@example.com")).toBe(true);
            expect(isValidEmail("user.name@example.co.uk")).toBe(true);
        });

        it("should reject invalid emails", () => {
            expect(isValidEmail("invalid")).toBe(false);
            expect(isValidEmail("@example.com")).toBe(false);
            expect(isValidEmail("user@")).toBe(false);
        });
    });

    describe("calculateEntropy", () => {
        it("should return 0 for empty string", () => {
            expect(calculateEntropy("")).toBe(0);
        });

        it("should return 0 for single repeated char", () => {
            expect(calculateEntropy("aaaaaaa")).toBe(0);
        });

        it("should return higher entropy for varied text", () => {
            const lowEntropy = calculateEntropy("aaabbb");
            const highEntropy = calculateEntropy("abcdef");
            expect(highEntropy).toBeGreaterThan(lowEntropy);
        });
    });
});
