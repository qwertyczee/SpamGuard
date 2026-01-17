// ============================================================================
// Language Dataset Schema
// Defines the structure for multilingual spam detection datasets
// ============================================================================

/**
 * Spam word entry with score and category
 */
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

/**
 * Spam subject pattern with regex and score
 */
export interface SpamSubjectPattern {
    pattern: string; // Regex pattern as string (will be compiled at runtime)
    score: number;
    name: string;
}

/**
 * Token probability for Bayesian analysis
 */
export interface TokenProbability {
    spam: number; // P(token|spam)
    ham: number; // P(token|ham)
}

/**
 * Complete language dataset for spam detection
 */
export interface LanguageDataset {
    /** ISO 639-1 language code (e.g., "en", "es", "fr") */
    language: string;

    /** Human-readable language name */
    languageName: string;

    /** Spam phrases and words with scores */
    spamWords: SpamWord[];

    /** Single word triggers (obfuscated words like "v1agra") */
    spamSingleWords: Record<string, number>;

    /** Subject line patterns (regex strings) */
    spamSubjectPatterns: SpamSubjectPattern[];

    /** Ham words that reduce spam score */
    hamWords: Record<string, number>;

    /** Bayesian token probabilities */
    bayesianTokens: Record<string, TokenProbability>;

    /** Urgency words for pattern matching */
    urgencyWords: string[];

    /** Greeting words (hello, dear, etc.) */
    greetingWords: string[];

    /** Generic greeting patterns (dear sir/madam, etc.) */
    genericGreetings: string[];
}

/**
 * Supported language codes - matches all languages from translate script
 * 109 languages total (English + 108 translations)
 */
export const SUPPORTED_LANGUAGES = [
    // English (base)
    "en",
    // Major European languages
    "es", "fr", "de", "pt", "it", "nl", "pl", "ru", "uk",
    "cs", "sk", "hu", "ro", "bg", "hr", "sr", "sl", "bs",
    "mk", "sq", "el", "tr",
    // Scandinavian languages
    "sv", "da", "no", "fi", "is",
    // Baltic languages
    "lt", "lv", "et",
    // Celtic languages
    "ga", "cy", "gd",
    // Asian languages
    "zh", "zh-TW", "ja", "ko", "vi", "th", "id", "ms", "tl",
    "hi", "bn", "ta", "te", "mr", "gu", "kn", "ml", "pa",
    "ur", "ne", "si", "my", "km", "lo", "mn", "ka", "hy",
    "az", "kk", "uz", "ky", "tg", "tk",
    // Middle Eastern languages
    "ar", "he", "fa", "ps", "ku",
    // African languages
    "sw", "am", "ha", "ig", "yo", "zu", "xh", "af", "so",
    "mg", "ny", "sn", "rw",
    // Other European languages
    "eu", "ca", "gl", "mt", "lb", "be",
    // South American indigenous
    "qu", "ay", "gn",
    // Pacific languages
    "mi", "sm", "haw",
    // South/Southeast Asian
    "jw", "su", "ceb", "hmn",
    // Constructed/Special
    "eo", "la",
    // Additional languages
    "ht", "yi", "co", "fy", "sd", "tt",
] as const;

export type SupportedLanguage = (typeof SUPPORTED_LANGUAGES)[number];

/**
 * Language names for display - matches translate script's LANGUAGES
 */
export const LANGUAGE_NAMES: Record<string, string> = {
    // English (base)
    en: "English",
    // Major European languages
    es: "Spanish",
    fr: "French",
    de: "German",
    pt: "Portuguese",
    it: "Italian",
    nl: "Dutch",
    pl: "Polish",
    ru: "Russian",
    uk: "Ukrainian",
    cs: "Czech",
    sk: "Slovak",
    hu: "Hungarian",
    ro: "Romanian",
    bg: "Bulgarian",
    hr: "Croatian",
    sr: "Serbian",
    sl: "Slovenian",
    bs: "Bosnian",
    mk: "Macedonian",
    sq: "Albanian",
    el: "Greek",
    tr: "Turkish",
    // Scandinavian languages
    sv: "Swedish",
    da: "Danish",
    no: "Norwegian",
    fi: "Finnish",
    is: "Icelandic",
    // Baltic languages
    lt: "Lithuanian",
    lv: "Latvian",
    et: "Estonian",
    // Celtic languages
    ga: "Irish",
    cy: "Welsh",
    gd: "Scottish Gaelic",
    // Asian languages
    zh: "Chinese (Simplified)",
    "zh-TW": "Chinese (Traditional)",
    ja: "Japanese",
    ko: "Korean",
    vi: "Vietnamese",
    th: "Thai",
    id: "Indonesian",
    ms: "Malay",
    tl: "Filipino (Tagalog)",
    hi: "Hindi",
    bn: "Bengali",
    ta: "Tamil",
    te: "Telugu",
    mr: "Marathi",
    gu: "Gujarati",
    kn: "Kannada",
    ml: "Malayalam",
    pa: "Punjabi",
    ur: "Urdu",
    ne: "Nepali",
    si: "Sinhala",
    my: "Myanmar (Burmese)",
    km: "Khmer",
    lo: "Lao",
    mn: "Mongolian",
    ka: "Georgian",
    hy: "Armenian",
    az: "Azerbaijani",
    kk: "Kazakh",
    uz: "Uzbek",
    ky: "Kyrgyz",
    tg: "Tajik",
    tk: "Turkmen",
    // Middle Eastern languages
    ar: "Arabic",
    he: "Hebrew",
    fa: "Persian (Farsi)",
    ps: "Pashto",
    ku: "Kurdish",
    // African languages
    sw: "Swahili",
    am: "Amharic",
    ha: "Hausa",
    ig: "Igbo",
    yo: "Yoruba",
    zu: "Zulu",
    xh: "Xhosa",
    af: "Afrikaans",
    so: "Somali",
    mg: "Malagasy",
    ny: "Chichewa",
    sn: "Shona",
    rw: "Kinyarwanda",
    // Other European languages
    eu: "Basque",
    ca: "Catalan",
    gl: "Galician",
    mt: "Maltese",
    lb: "Luxembourgish",
    be: "Belarusian",
    // South American indigenous
    qu: "Quechua",
    ay: "Aymara",
    gn: "Guarani",
    // Pacific languages
    mi: "Maori",
    sm: "Samoan",
    haw: "Hawaiian",
    // South/Southeast Asian
    jw: "Javanese",
    su: "Sundanese",
    ceb: "Cebuano",
    hmn: "Hmong",
    // Constructed/Special
    eo: "Esperanto",
    la: "Latin",
    // Additional languages
    ht: "Haitian Creole",
    yi: "Yiddish",
    co: "Corsican",
    fy: "Frisian",
    sd: "Sindhi",
    tt: "Tatar",
};

/**
 * Check if a language code is supported
 */
export function isSupportedLanguage(code: string): code is SupportedLanguage {
    return SUPPORTED_LANGUAGES.includes(code as SupportedLanguage);
}
