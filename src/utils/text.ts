// ============================================================================
// Text Analysis Utilities
// ============================================================================

import type { TextStats } from "../types";

/**
 * Calculate comprehensive text statistics
 */
export function calculateTextStats(text: string): TextStats {
    const chars = text.length;
    const words = text.split(/\s+/).filter((w) => w.length > 0);
    const wordCount = words.length;
    const lines = text.split(/\n/).length;

    // Character analysis
    const upperCount = (text.match(/[A-Z]/g) || []).length;
    const digitCount = (text.match(/\d/g) || []).length;
    const specialCount = (text.match(/[^a-zA-Z0-9\s]/g) || []).length;
    const letterCount = (text.match(/[a-zA-Z]/g) || []).length;

    // Word analysis
    const wordLengths = words.map((w) => w.length);
    const avgWordLength =
        wordCount > 0 ? wordLengths.reduce((a, b) => a + b, 0) / wordCount : 0;

    const shortWords = words.filter((w) => w.length <= 3).length;
    const longWords = words.filter((w) => w.length >= 10).length;

    return {
        charCount: chars,
        wordCount,
        lineCount: lines,
        uppercaseRatio: letterCount > 0 ? upperCount / letterCount : 0,
        digitRatio: chars > 0 ? digitCount / chars : 0,
        specialCharRatio: chars > 0 ? specialCount / chars : 0,
        avgWordLength,
        shortWordRatio: wordCount > 0 ? shortWords / wordCount : 0,
        longWordRatio: wordCount > 0 ? longWords / wordCount : 0,
    };
}

/**
 * Extract all URLs from text
 */
export function extractUrls(text: string): string[] {
    const urlPattern = /https?:\/\/[^\s<>"')\]]+/gi;
    const matches = text.match(urlPattern) || [];

    // Clean up URLs (remove trailing punctuation)
    return matches.map((url) => url.replace(/[.,;:!?)]+$/, ""));
}

/**
 * Extract all email addresses from text
 */
export function extractEmails(text: string): string[] {
    const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    return text.match(emailPattern) || [];
}

/**
 * Simple language detection based on character patterns
 */
export function detectLanguage(text: string): string {
    // Very simple heuristic based on character frequency
    const cyrillicCount = (text.match(/[а-яА-ЯёЁ]/g) || []).length;
    const latinCount = (text.match(/[a-zA-Z]/g) || []).length;
    const chineseCount = (text.match(/[\u4e00-\u9fff]/g) || []).length;
    const arabicCount = (text.match(/[\u0600-\u06FF]/g) || []).length;

    const total = cyrillicCount + latinCount + chineseCount + arabicCount;
    if (total === 0) return "unknown";

    if (cyrillicCount / total > 0.5) return "cyrillic";
    if (chineseCount / total > 0.5) return "chinese";
    if (arabicCount / total > 0.5) return "arabic";
    return "latin";
}

/**
 * Normalize text for analysis (lowercase, remove extra whitespace)
 */
export function normalizeText(text: string): string {
    return text.toLowerCase().replace(/\s+/g, " ").trim();
}

/**
 * Extract visible text from HTML
 */
export function extractTextFromHtml(html: string): string {
    // Remove script and style tags
    let text = html
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "")
        .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, "");

    // Remove HTML comments
    text = text.replace(/<!--[\s\S]*?-->/g, "");

    // Replace block elements with newlines
    text = text.replace(/<\/(p|div|br|h[1-6]|li|tr)>/gi, "\n");

    // Remove all remaining HTML tags
    text = text.replace(/<[^>]+>/g, " ");

    // Decode HTML entities
    text = decodeHtmlEntities(text);

    // Clean up whitespace
    text = text.replace(/\s+/g, " ").trim();

    return text;
}

/**
 * Decode common HTML entities
 */
export function decodeHtmlEntities(text: string): string {
    const entities: Record<string, string> = {
        "&amp;": "&",
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&#39;": "'",
        "&apos;": "'",
        "&nbsp;": " ",
        "&copy;": "©",
        "&reg;": "®",
        "&trade;": "™",
    };

    let result = text;
    for (const [entity, char] of Object.entries(entities)) {
        result = result.replace(new RegExp(entity, "gi"), char);
    }

    // Decode numeric entities
    result = result.replace(/&#(\d+);/g, (_, num) => {
        return String.fromCharCode(parseInt(num, 10));
    });

    result = result.replace(/&#x([0-9a-f]+);/gi, (_, hex) => {
        return String.fromCharCode(parseInt(hex, 16));
    });

    return result;
}

/**
 * Calculate similarity between two strings (Levenshtein distance based)
 */
export function stringSimilarity(a: string, b: string): number {
    if (a === b) return 1;
    if (a.length === 0 || b.length === 0) return 0;

    const longer = a.length > b.length ? a : b;
    const shorter = a.length > b.length ? b : a;

    const longerLength = longer.length;
    if (longerLength === 0) return 1;

    const distance = levenshteinDistance(longer, shorter);
    return (longerLength - distance) / longerLength;
}

function levenshteinDistance(a: string, b: string): number {
    const matrix: number[][] = [];

    for (let i = 0; i <= b.length; i++) {
        matrix[i] = [i];
    }

    for (let j = 0; j <= a.length; j++) {
        matrix[0][j] = j;
    }

    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {
            if (b.charAt(i - 1) === a.charAt(j - 1)) {
                matrix[i][j] = matrix[i - 1][j - 1];
            } else {
                matrix[i][j] = Math.min(
                    matrix[i - 1][j - 1] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j] + 1,
                );
            }
        }
    }

    return matrix[b.length][a.length];
}

/**
 * Check if text contains invisible characters
 */
export function hasInvisibleChars(text: string): boolean {
    // Zero-width characters
    const invisiblePattern = /[\u200B-\u200D\u2060\uFEFF\u00AD]/;
    return invisiblePattern.test(text);
}

/**
 * Check for homograph attacks (mixed scripts)
 */
export function hasMixedScripts(text: string): boolean {
    const hasLatin = /[a-zA-Z]/.test(text);
    const hasCyrillic = /[а-яА-ЯёЁ]/.test(text);
    const hasGreek = /[α-ωΑ-Ω]/.test(text);

    const scriptCount = [hasLatin, hasCyrillic, hasGreek].filter(
        Boolean,
    ).length;
    return scriptCount > 1;
}

/**
 * Extract domain from email address
 */
export function getDomainFromEmail(email: string): string {
    const parts = email.split("@");
    return parts.length > 1 ? parts[1].toLowerCase() : "";
}

/**
 * Check if string is a valid email format
 */
export function isValidEmail(email: string): boolean {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(email);
}

/**
 * Calculate entropy of text (randomness measure)
 */
export function calculateEntropy(text: string): number {
    if (text.length === 0) return 0;

    const freq = new Map<string, number>();
    for (const char of text) {
        freq.set(char, (freq.get(char) || 0) + 1);
    }

    let entropy = 0;
    const len = text.length;

    for (const count of freq.values()) {
        const p = count / len;
        entropy -= p * Math.log2(p);
    }

    return entropy;
}
