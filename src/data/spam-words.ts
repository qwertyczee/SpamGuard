// ============================================================================
// Spam Words Database
// Based on patterns from SpamAssassin, DNSBL research, and common spam corpus
// ============================================================================

export interface SpamWord {
    word: string;
    score: number;
    category:
        | "finance"
        | "urgency"
        | "adult"
        | "health"
        | "scam"
        | "marketing"
        | "phishing"
        | "lottery"
        | "drugs"
        | "crypto";
    caseSensitive?: boolean;
}

// High-confidence spam indicators
export const SPAM_WORDS: SpamWord[] = [
    // Financial scams
    { word: "nigerian prince", score: 3.5, category: "scam" },
    { word: "wire transfer", score: 1.5, category: "finance" },
    { word: "bank account details", score: 2.0, category: "phishing" },
    { word: "inheritance fund", score: 3.0, category: "scam" },
    { word: "unclaimed funds", score: 3.0, category: "scam" },
    { word: "beneficiary", score: 1.0, category: "scam" },
    { word: "million dollars", score: 2.0, category: "scam" },
    { word: "million usd", score: 2.0, category: "scam" },
    { word: "transfer fee", score: 1.5, category: "scam" },
    { word: "processing fee", score: 1.0, category: "scam" },
    { word: "advance fee", score: 2.0, category: "scam" },
    { word: "western union", score: 1.5, category: "finance" },
    { word: "moneygram", score: 1.5, category: "finance" },
    { word: "bitcoin wallet", score: 1.0, category: "crypto" },
    { word: "cryptocurrency investment", score: 1.5, category: "crypto" },
    { word: "double your bitcoin", score: 3.0, category: "crypto" },
    { word: "crypto giveaway", score: 2.5, category: "crypto" },

    // Urgency
    { word: "act now", score: 1.5, category: "urgency" },
    { word: "act immediately", score: 1.8, category: "urgency" },
    { word: "urgent response", score: 1.5, category: "urgency" },
    { word: "urgent attention", score: 1.5, category: "urgency" },
    { word: "immediate action", score: 1.5, category: "urgency" },
    { word: "limited time", score: 1.0, category: "urgency" },
    { word: "expires today", score: 1.2, category: "urgency" },
    { word: "last chance", score: 1.0, category: "urgency" },
    { word: "final notice", score: 1.5, category: "urgency" },
    { word: "respond immediately", score: 1.5, category: "urgency" },
    { word: "within 24 hours", score: 1.0, category: "urgency" },
    { word: "within 48 hours", score: 0.8, category: "urgency" },
    { word: "time sensitive", score: 1.0, category: "urgency" },
    { word: "don't delay", score: 1.0, category: "urgency" },

    // Lottery / Prize scams
    { word: "congratulations winner", score: 2.5, category: "lottery" },
    { word: "you have won", score: 2.0, category: "lottery" },
    { word: "lottery winner", score: 2.5, category: "lottery" },
    { word: "prize notification", score: 2.0, category: "lottery" },
    { word: "claim your prize", score: 2.0, category: "lottery" },
    { word: "winning notification", score: 2.0, category: "lottery" },
    { word: "lucky winner", score: 2.0, category: "lottery" },
    { word: "selected winner", score: 1.5, category: "lottery" },
    { word: "cash prize", score: 1.5, category: "lottery" },
    { word: "free prize", score: 1.5, category: "lottery" },
    { word: "sweepstakes", score: 1.0, category: "lottery" },

    // Phishing
    { word: "verify your account", score: 2.0, category: "phishing" },
    { word: "confirm your identity", score: 1.5, category: "phishing" },
    { word: "update your payment", score: 2.0, category: "phishing" },
    { word: "suspended account", score: 1.8, category: "phishing" },
    { word: "account suspended", score: 1.8, category: "phishing" },
    { word: "unusual activity", score: 1.2, category: "phishing" },
    { word: "suspicious activity", score: 1.2, category: "phishing" },
    { word: "unauthorized access", score: 1.2, category: "phishing" },
    { word: "click here to verify", score: 2.0, category: "phishing" },
    { word: "login credentials", score: 1.5, category: "phishing" },
    { word: "password reset", score: 0.8, category: "phishing" },
    { word: "security alert", score: 1.0, category: "phishing" },
    { word: "your account will be", score: 1.5, category: "phishing" },
    { word: "failure to verify", score: 1.8, category: "phishing" },
    { word: "reactivate your", score: 1.5, category: "phishing" },

    // Marketing spam
    { word: "unsubscribe", score: 0.1, category: "marketing" },
    { word: "click here", score: 0.8, category: "marketing" },
    { word: "buy now", score: 1.0, category: "marketing" },
    { word: "order now", score: 0.8, category: "marketing" },
    { word: "free offer", score: 1.2, category: "marketing" },
    { word: "special offer", score: 0.8, category: "marketing" },
    { word: "exclusive deal", score: 0.8, category: "marketing" },
    { word: "risk free", score: 1.2, category: "marketing" },
    { word: "no obligation", score: 0.8, category: "marketing" },
    { word: "money back guarantee", score: 0.8, category: "marketing" },
    { word: "satisfaction guaranteed", score: 0.5, category: "marketing" },
    { word: "call now", score: 0.8, category: "marketing" },
    { word: "toll free", score: 0.5, category: "marketing" },
    { word: "100% free", score: 1.2, category: "marketing" },
    { word: "completely free", score: 1.0, category: "marketing" },
    { word: "no cost", score: 0.8, category: "marketing" },
    { word: "no fees", score: 0.8, category: "marketing" },
    { word: "lowest price", score: 0.8, category: "marketing" },
    { word: "best price", score: 0.5, category: "marketing" },
    { word: "discount", score: 0.3, category: "marketing" },
    { word: "save big", score: 0.8, category: "marketing" },
    { word: "save money", score: 0.5, category: "marketing" },
    { word: "double your", score: 1.5, category: "marketing" },
    { word: "increase your", score: 0.5, category: "marketing" },
    { word: "earn money", score: 1.0, category: "marketing" },
    { word: "make money", score: 1.0, category: "marketing" },
    { word: "extra income", score: 1.0, category: "marketing" },
    { word: "work from home", score: 1.2, category: "marketing" },
    { word: "be your own boss", score: 1.2, category: "marketing" },
    { word: "financial freedom", score: 1.0, category: "marketing" },
    { word: "get rich", score: 1.5, category: "marketing" },
    { word: "get paid", score: 0.8, category: "marketing" },
    { word: "instant access", score: 0.8, category: "marketing" },
    { word: "join millions", score: 1.0, category: "marketing" },

    // Health / Pharma spam
    { word: "viagra", score: 2.5, category: "drugs" },
    { word: "cialis", score: 2.5, category: "drugs" },
    { word: "pharmacy", score: 0.8, category: "drugs" },
    { word: "online pharmacy", score: 1.5, category: "drugs" },
    { word: "canadian pharmacy", score: 1.8, category: "drugs" },
    { word: "prescription", score: 0.5, category: "drugs" },
    { word: "no prescription", score: 2.0, category: "drugs" },
    { word: "without prescription", score: 2.0, category: "drugs" },
    { word: "erectile dysfunction", score: 1.5, category: "drugs" },
    { word: "weight loss", score: 1.0, category: "health" },
    { word: "lose weight", score: 1.0, category: "health" },
    { word: "lose pounds", score: 1.0, category: "health" },
    { word: "diet pill", score: 1.5, category: "health" },
    { word: "fat burner", score: 1.5, category: "health" },
    { word: "miracle cure", score: 2.0, category: "health" },
    { word: "natural remedy", score: 0.8, category: "health" },
    { word: "anti-aging", score: 0.8, category: "health" },

    // Adult content
    { word: "adult content", score: 1.5, category: "adult" },
    { word: "xxx", score: 2.0, category: "adult" },
    { word: "adult dating", score: 2.0, category: "adult" },
    { word: "meet singles", score: 1.2, category: "adult" },
    { word: "hot singles", score: 2.0, category: "adult" },
    { word: "lonely women", score: 2.0, category: "adult" },
    { word: "lonely housewife", score: 2.5, category: "adult" },

    // General scam indicators
    { word: "dear friend", score: 1.5, category: "scam" },
    { word: "dear beloved", score: 2.0, category: "scam" },
    { word: "dear sir/madam", score: 0.8, category: "scam" },
    { word: "confidential", score: 0.8, category: "scam" },
    { word: "strictly confidential", score: 1.5, category: "scam" },
    { word: "private and confidential", score: 1.5, category: "scam" },
    { word: "do not ignore", score: 1.5, category: "urgency" },
    { word: "must respond", score: 1.2, category: "urgency" },
    { word: "this is not spam", score: 2.5, category: "scam" },
    { word: "this is not junk", score: 2.5, category: "scam" },
    { word: "not a scam", score: 2.5, category: "scam" },
    { word: "legitimate offer", score: 1.5, category: "scam" },
    { word: "legal notice", score: 1.0, category: "scam" },
    { word: "court order", score: 1.5, category: "scam" },
    { word: "government grant", score: 2.0, category: "scam" },
    { word: "free grant", score: 2.0, category: "scam" },
    { word: "irs", score: 0.8, category: "scam" },
    { word: "tax refund", score: 1.5, category: "scam" },
];

// Single word triggers (higher precision)
export const SPAM_SINGLE_WORDS: Map<string, number> = new Map([
    // Very high confidence
    ["v1agra", 3.0],
    ["vi@gra", 3.0],
    ["c1alis", 3.0],
    ["p0rn", 3.0],
    ["pr0n", 3.0],
    ["s3x", 2.0],

    // High confidence
    ["enlargement", 1.5],
    ["erectile", 1.2],
    ["orgasm", 1.5],
    ["libido", 1.2],
    ["potency", 1.2],

    // Medium confidence
    ["unsubscribe", 0.3],
    ["opt-out", 0.3],
    ["optout", 0.3],
    ["junk", 0.5],
    ["bulk", 0.5],
    ["mass", 0.3],
    ["mlm", 1.5],
    ["roi", 0.5],
]);

// Patterns that often appear in spam subjects
export const SPAM_SUBJECT_PATTERNS: Array<{
    pattern: RegExp;
    score: number;
    name: string;
}> = [
    { pattern: /^re:\s*re:\s*re:/i, score: 1.5, name: "MULTIPLE_RE" },
    { pattern: /^fw:\s*fw:\s*fw:/i, score: 1.5, name: "MULTIPLE_FW" },
    { pattern: /^re:\s*$/i, score: 2.0, name: "EMPTY_RE" },
    { pattern: /\$\$\$/, score: 2.0, name: "DOLLAR_SIGNS" },
    { pattern: /!\s*!\s*!/, score: 1.5, name: "MULTIPLE_EXCLAIM" },
    { pattern: /\?\s*\?\s*\?/, score: 1.0, name: "MULTIPLE_QUESTION" },
    { pattern: /[A-Z]{10,}/, score: 1.5, name: "LONG_CAPS" },
    {
        pattern: /free\s+(gift|money|cash|prize)/i,
        score: 2.0,
        name: "FREE_STUFF",
    },
    {
        pattern: /you('ve|'re|\s+have|\s+are)\s+(been\s+)?selected/i,
        score: 2.0,
        name: "YOU_SELECTED",
    },
    { pattern: /winner/i, score: 1.2, name: "WINNER" },
    { pattern: /urgent/i, score: 1.0, name: "URGENT" },
    {
        pattern: /important\s+(notice|message|information)/i,
        score: 1.2,
        name: "IMPORTANT_NOTICE",
    },
    {
        pattern: /account\s+(suspended|closed|locked)/i,
        score: 1.8,
        name: "ACCOUNT_SUSPENDED",
    },
    { pattern: /verify\s+(your|account)/i, score: 1.5, name: "VERIFY_ACCOUNT" },
    { pattern: /\d{1,3}%\s*off/i, score: 0.8, name: "PERCENT_OFF" },
    { pattern: /limited\s+time/i, score: 1.0, name: "LIMITED_TIME" },
    { pattern: /act\s+now/i, score: 1.5, name: "ACT_NOW" },
    { pattern: /call\s+now/i, score: 1.0, name: "CALL_NOW" },
    { pattern: /\bATTN\b/i, score: 1.0, name: "ATTN" },
    {
        pattern: /dear\s+(customer|user|member|valued)/i,
        score: 1.0,
        name: "DEAR_GENERIC",
    },
];

// Common ham words (reduce spam score)
export const HAM_WORDS: Map<string, number> = new Map([
    ["meeting", -0.3],
    ["schedule", -0.3],
    ["project", -0.3],
    ["deadline", -0.3],
    ["attached", -0.3],
    ["attachment", -0.3],
    ["regards", -0.2],
    ["sincerely", -0.2],
    ["thanks", -0.2],
    ["thank you", -0.3],
    ["following up", -0.3],
    ["as discussed", -0.5],
    ["per our conversation", -0.5],
    ["invoice", -0.2],
    ["report", -0.2],
    ["summary", -0.2],
    ["minutes", -0.3],
    ["agenda", -0.3],
    ["conference", -0.3],
    ["repository", -0.5],
    ["pull request", -0.8],
    ["commit", -0.5],
    ["merge", -0.5],
    ["branch", -0.5],
    ["deploy", -0.5],
    ["documentation", -0.3],
]);
