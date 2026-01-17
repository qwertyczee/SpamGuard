// ============================================================================
// Language Dataset Loader
// Loads and manages multilingual spam detection datasets with dynamic imports
// ============================================================================

import type {
    LanguageDataset,
    SpamWord,
    SpamSubjectPattern,
    TokenProbability,
} from "./schema";
import { SUPPORTED_LANGUAGES, LANGUAGE_NAMES, isSupportedLanguage } from "./schema";

// English as fallback (always available)
import enData from "./en.json";

/**
 * Type for the raw JSON data (before processing)
 */
interface RawLanguageData {
    language: string;
    languageName: string;
    spamWords: SpamWord[];
    spamSingleWords: Record<string, number>;
    spamSubjectPatterns: Array<{ pattern: string; score: number; name: string }>;
    hamWords: Record<string, number>;
    bayesianTokens: Record<string, TokenProbability>;
    urgencyWords: string[];
    greetingWords: string[];
    genericGreetings: string[];
}

/**
 * Process raw JSON data into a LanguageDataset
 */
function processDataset(raw: RawLanguageData): LanguageDataset {
    return {
        language: raw.language,
        languageName: raw.languageName,
        spamWords: raw.spamWords,
        spamSingleWords: raw.spamSingleWords,
        spamSubjectPatterns: raw.spamSubjectPatterns.map((p) => ({
            pattern: p.pattern,
            score: p.score,
            name: p.name,
        })),
        hamWords: raw.hamWords,
        bayesianTokens: raw.bayesianTokens,
        urgencyWords: raw.urgencyWords,
        greetingWords: raw.greetingWords,
        genericGreetings: raw.genericGreetings,
    };
}

/**
 * Get English dataset (sync, always available)
 */
export function getEnglishData(): LanguageDataset {
    return processDataset(enData as RawLanguageData);
}

/**
 * Get a language dataset by language code
 * Dynamically imports the language file, falls back to English if not found
 *
 * @param langCode - ISO 639-1 language code (e.g., "en", "es")
 * @returns Promise resolving to Language dataset
 */
export async function getLanguageData(langCode: string): Promise<LanguageDataset> {
    const normalizedCode = langCode.toLowerCase().trim();

    // English is always available via static import
    if (normalizedCode === "en") {
        return processDataset(enData as RawLanguageData);
    }

    try {
        // Dynamic import of the language file
        const module = await import(`./${normalizedCode}.json`);
        return processDataset(module.default as RawLanguageData);
    } catch {
        // File doesn't exist, fall back to English
        return processDataset(enData as RawLanguageData);
    }
}

/**
 * Get list of available languages
 */
export function getAvailableLanguages(): readonly string[] {
    return SUPPORTED_LANGUAGES;
}

/**
 * Get language name for display
 */
export function getLanguageName(langCode: string): string {
    const normalizedCode = langCode.toLowerCase().trim();
    return LANGUAGE_NAMES[normalizedCode as keyof typeof LANGUAGE_NAMES] || langCode;
}

/**
 * Get spam words for a language
 */
export async function getSpamWords(langCode: string): Promise<SpamWord[]> {
    const data = await getLanguageData(langCode);
    return data.spamWords;
}

/**
 * Get ham words for a language
 */
export async function getHamWords(langCode: string): Promise<Record<string, number>> {
    const data = await getLanguageData(langCode);
    return data.hamWords;
}

/**
 * Get Bayesian tokens for a language
 */
export async function getBayesianTokens(langCode: string): Promise<Record<string, TokenProbability>> {
    const data = await getLanguageData(langCode);
    return data.bayesianTokens;
}

/**
 * Get urgency words for a language
 */
export async function getUrgencyWords(langCode: string): Promise<string[]> {
    const data = await getLanguageData(langCode);
    return data.urgencyWords;
}

// Re-export types and utilities from schema
export type { LanguageDataset, SpamWord, SpamSubjectPattern, TokenProbability };
export { SUPPORTED_LANGUAGES, LANGUAGE_NAMES, isSupportedLanguage };
export type { SupportedLanguage } from "./schema";
