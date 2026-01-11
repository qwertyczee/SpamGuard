// ============================================================================
// Spam Detection Patterns
// Regular expressions for various spam indicators
// ============================================================================

export interface PatternRule {
    name: string;
    pattern: RegExp;
    score: number;
    description: string;
    category:
        | "obfuscation"
        | "formatting"
        | "content"
        | "structure"
        | "encoding";
}

// Text obfuscation patterns (spammers trying to evade filters)
export const OBFUSCATION_PATTERNS: PatternRule[] = [
    {
        name: "SPACED_WORDS",
        pattern: /\b[a-z]\s+[a-z]\s+[a-z]\s+[a-z]\s+[a-z]\b/i,
        score: 1.5,
        description: "Words with spaces between letters (f r e e)",
        category: "obfuscation",
    },
    {
        name: "LETTER_NUMBER_SUBSTITUTION",
        pattern: /[a-z][0-9][a-z]|[0-9][a-z][0-9]/i,
        score: 0.8,
        description: "Letters and numbers mixed (v1agra, fr33)",
        category: "obfuscation",
    },
    {
        name: "SYMBOL_SUBSTITUTION",
        pattern: /[a-z](?:[$!]|@(?![a-z0-9-]+\.[a-z]{2,}))[a-z]/i,
        score: 1.0,
        description: "Symbols substituted for letters (vi@gra)",
        category: "obfuscation",
    },
    {
        name: "ZERO_WIDTH_CHARS",
        pattern: /[\u200B-\u200D\uFEFF]/,
        score: 2.5,
        description: "Zero-width characters hidden in text",
        category: "obfuscation",
    },
    {
        name: "HOMOGRAPH_ATTACK",
        pattern: /[а-яА-Я]|[αβγδεζηθικλμνξοπρστυφχψω]/,
        score: 1.5,
        description: "Cyrillic or Greek characters that look like Latin",
        category: "obfuscation",
    },
    {
        name: "EXCESSIVE_PUNCTUATION",
        pattern: /[!?]{3,}/,
        score: 1.0,
        description: "Multiple exclamation or question marks",
        category: "obfuscation",
    },
    {
        name: "REPEATED_CHARS",
        pattern: /(\S)\1{4,}/,
        score: 1.0,
        description: "Same character repeated many times",
        category: "obfuscation",
    },
];

// Formatting patterns
export const FORMATTING_PATTERNS: PatternRule[] = [
    {
        name: "ALL_CAPS_BLOCK",
        pattern: /[A-Z\s]{30,}/,
        score: 1.5,
        description: "Large block of uppercase text",
        category: "formatting",
    },
    {
        name: "EXCESSIVE_WHITESPACE",
        pattern: /\n{5,}|\s{10,}/,
        score: 0.8,
        description: "Excessive blank lines or spaces",
        category: "formatting",
    },
    {
        name: "RANDOM_CAPS",
        pattern: /([A-Z][a-z]){5,}/,
        score: 1.0,
        description: "Alternating caps pattern (HeLlO WoRlD)",
        category: "formatting",
    },
];

// Content patterns
export const CONTENT_PATTERNS: PatternRule[] = [
    {
        name: "CURRENCY_AMOUNT",
        pattern:
            /[$€£¥]\s*\d{1,3}(?:,\d{3})*(?:\.\d{2})?|\d{1,3}(?:,\d{3})*(?:\.\d{2})?\s*(?:dollars?|USD|EUR|GBP)/gi,
        score: 0.5,
        description: "Currency amounts mentioned",
        category: "content",
    },
    {
        name: "LARGE_MONEY_AMOUNT",
        pattern:
            /[$€£¥]\s*\d{1,3}(?:,\d{3}){2,}|(?:million|billion)\s+(?:dollars?|USD|EUR)/gi,
        score: 1.5,
        description: "Large money amounts (millions)",
        category: "content",
    },
    {
        name: "PERCENTAGE_CLAIM",
        pattern: /\d{2,3}\s*%\s*(?:off|discount|free|guaranteed|success)/i,
        score: 1.0,
        description: "Percentage claims (90% off, 100% free)",
        category: "content",
    },
    {
        name: "PHONE_NUMBER_SPAM",
        pattern:
            /(?:call|dial|phone|tel|contact)\s*(?:us)?\s*(?:at|:)?\s*[\d\-\(\)\s]{10,}/i,
        score: 0.8,
        description: "Phone number with call to action",
        category: "content",
    },
    {
        name: "TRACKING_NUMBER_FAKE",
        pattern: /tracking\s*(?:number|#|no\.?|code)?\s*:?\s*[A-Z0-9]{10,}/i,
        score: 1.2,
        description: "Fake tracking number pattern",
        category: "content",
    },
    {
        name: "LOTTERY_REFERENCE",
        pattern:
            /\b(?:ref|reference|ticket|batch|lucky)\s*(?:number|#|no\.?|code)?\s*:?\s*[A-Z0-9]{8,}/i,
        score: 1.5,
        description: "Lottery-style reference numbers",
        category: "content",
    },
    {
        name: "NIGERIAN_SCAM_MARKERS",
        pattern:
            /(?:next of kin|deceased|inheritance|barrister|solicitor|diplomat|consignment|trunk box)/i,
        score: 2.0,
        description: "Classic 419 scam terminology",
        category: "content",
    },
    {
        name: "URGENCY_CAPS",
        pattern:
            /\b(?:URGENT|IMPORTANT|ATTENTION|WARNING|ALERT|IMMEDIATE|FINAL)\b/,
        score: 1.2,
        description: "Urgency words in all caps",
        category: "content",
    },
    {
        name: "CRYPTO_SCAM",
        pattern:
            /(?:bitcoin|btc|ethereum|eth|crypto)\s*(?:investment|trading|profit|wallet|giveaway)/i,
        score: 1.8,
        description: "Cryptocurrency scam patterns",
        category: "content",
    },
    {
        name: "DATING_SCAM",
        pattern:
            /(?:beautiful|lonely|single)\s*(?:woman|lady|girl|man)\s*(?:looking|seeking|wants)/i,
        score: 3.0,
        description: "Dating/romance scam patterns",
        category: "content",
    },
];

// Structure patterns (how the email is organized)
export const STRUCTURE_PATTERNS: PatternRule[] = [
    {
        name: "VERY_SHORT_BODY",
        pattern: /^.{0,20}$/s,
        score: 0.5,
        description: "Very short email body",
        category: "structure",
    },
    {
        name: "NO_GREETING",
        pattern:
            /^(?!(?:hi|hello|dear|hey|good\s+(?:morning|afternoon|evening)|greetings))/i,
        score: 0.1,
        description: "No greeting at start",
        category: "structure",
    },
    {
        name: "GENERIC_GREETING",
        pattern:
            /^(?:dear\s+(?:sir|madam|customer|user|member|friend|valued|recipient|beneficiary))/i,
        score: 1.2,
        description: "Generic impersonal greeting",
        category: "structure",
    },
    {
        name: "MULTIPLE_URLS",
        pattern: /https?:\/\/[^\s]+(?:.*https?:\/\/[^\s]+){4,}/is,
        score: 1.0,
        description: "Multiple URLs in body",
        category: "structure",
    },
    {
        name: "URL_ONLY_BODY",
        pattern: /^(?:\s*https?:\/\/[^\s]+\s*)+$/i,
        score: 2.0,
        description: "Body contains only URLs",
        category: "structure",
    },
    {
        name: "HIDDEN_TEXT_MARKER",
        pattern:
            /font-size:\s*0|display:\s*none|visibility:\s*hidden|color:\s*(?:#fff(?:fff)?|white|#f{6})\s*;[^}]*background/i,
        score: 2.5,
        description: "CSS hiding text",
        category: "structure",
    },
];

// Base64 and encoding patterns
export const ENCODING_PATTERNS: PatternRule[] = [
    {
        name: "BASE64_BLOCK",
        pattern: /[A-Za-z0-9+\/]{50,}={0,2}/,
        score: 0.5,
        description: "Large Base64 encoded block in body",
        category: "encoding",
    },
    {
        name: "ENCODED_URL",
        pattern: /(?:%[0-9A-Fa-f]{2}){5,}/,
        score: 1.2,
        description: "Heavily URL-encoded content",
        category: "encoding",
    },
    {
        name: "HTML_ENTITIES_ABUSE",
        pattern: /(?:&#\d{2,4};){5,}|(?:&[a-z]+;){5,}/i,
        score: 1.5,
        description: "Excessive HTML entities",
        category: "encoding",
    },
];

// Combine all patterns
export const ALL_PATTERNS: PatternRule[] = [
    ...OBFUSCATION_PATTERNS,
    ...FORMATTING_PATTERNS,
    ...CONTENT_PATTERNS,
    ...STRUCTURE_PATTERNS,
    ...ENCODING_PATTERNS,
];
