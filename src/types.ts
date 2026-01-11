// ============================================================================
// SpamGuard Types
// ============================================================================

export interface EmailInput {
    // Headers
    from?: string;
    to?: string | string[];
    subject?: string;
    messageId?: string;
    date?: string;
    replyTo?: string;
    returnPath?: string;

    // Authentication headers
    receivedSpf?: string;
    dkimSignature?: string;
    authenticationResults?: string;

    // All headers as raw object
    headers?: Record<string, string | string[]>;

    // Content
    textBody?: string;
    htmlBody?: string;

    // Metadata
    clientIp?: string;
    helo?: string;

    // Raw email (MIME format)
    raw?: string;
}

export interface AnalysisRule {
    name: string;
    description: string;
    score: number;
    category: RuleCategory;
}

export type RuleCategory =
    | "header"
    | "content"
    | "url"
    | "html"
    | "pattern"
    | "bayesian"
    | "authentication"
    | "reputation";

export interface RuleMatch {
    rule: AnalysisRule;
    matched: boolean;
    details?: string;
    evidence?: string[];
}

export interface AnalyzerResult {
    analyzer: string;
    score: number;
    maxScore: number;
    matches: RuleMatch[];
    metadata?: Record<string, unknown>;
}

export interface SpamAnalysisResult {
    // Final verdict
    isSpam: boolean;
    score: number;
    threshold: number;
    confidence: number;

    // Classification
    classification: "ham" | "spam" | "probable_spam" | "probable_ham";

    // Detailed results
    analyzers: AnalyzerResult[];

    // Summary
    topReasons: string[];

    // Timing
    processingTimeMs: number;

    // Debug info
    debug?: {
        extractedUrls?: string[];
        extractedEmails?: string[];
        languageDetected?: string;
        textStats?: TextStats;
    };
}

export interface TextStats {
    charCount: number;
    wordCount: number;
    lineCount: number;
    uppercaseRatio: number;
    digitRatio: number;
    specialCharRatio: number;
    avgWordLength: number;
    shortWordRatio: number;
    longWordRatio: number;
}

export interface ParsedEmail {
    headers: Map<string, string[]>;
    subject: string;
    from: EmailAddress | null;
    to: EmailAddress[];
    replyTo: EmailAddress | null;
    returnPath: string | null;
    messageId: string | null;
    date: Date | null;
    textBody: string;
    htmlBody: string;
    attachments: Attachment[];
    receivedChain: ReceivedHeader[];
}

export interface EmailAddress {
    name: string | null;
    address: string;
    domain: string;
    localPart: string;
}

export interface Attachment {
    filename: string;
    contentType: string;
    size: number;
    isInline: boolean;
}

export interface ReceivedHeader {
    from: string | null;
    by: string | null;
    with: string | null;
    timestamp: Date | null;
    raw: string;
}

export interface UrlInfo {
    original: string;
    protocol: string;
    domain: string;
    tld: string;
    path: string;
    query: string;
    isIpAddress: boolean;
    isSuspiciousTld: boolean;
    hasPortNumber: boolean;
    isShortener: boolean;
    encodedChars: boolean;
}

// Bayesian token
export interface BayesianToken {
    token: string;
    spamProbability: number;
    hamProbability: number;
    weight: number;
}

// Configuration
export interface SpamGuardConfig {
    spamThreshold: number;
    probableSpamThreshold: number;
    enableDebug: boolean;
}

export const DEFAULT_CONFIG: SpamGuardConfig = {
    spamThreshold: 3.5,
    probableSpamThreshold: 2.0,
    enableDebug: false,
};
