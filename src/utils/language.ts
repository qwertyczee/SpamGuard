// ============================================================================
// Language Detection Utility
// Uses franc library for accurate language detection
// ============================================================================

import { franc, francAll } from "franc";
import {
    SUPPORTED_LANGUAGES,
    type SupportedLanguage,
    isSupportedLanguage,
} from "../data/languages/schema";

/**
 * Result of language detection
 */
export interface LanguageDetectionResult {
    /** ISO 639-1 language code (e.g., "en", "es", "fr") */
    code: SupportedLanguage;
    /** Confidence score between 0 and 1 */
    confidence: number;
    /** Whether the detected language is supported */
    isSupported: boolean;
    /** Original detected code before mapping (ISO 639-3) */
    rawCode: string;
}

/**
 * Map from ISO 639-3 (franc output) to ISO 639-1 (our codes)
 * Comprehensive mapping for 100+ languages
 */
const ISO_639_3_TO_639_1: Record<string, string> = {
    // Major European languages
    eng: "en",
    spa: "es",
    fra: "fr",
    deu: "de",
    por: "pt",
    ita: "it",
    nld: "nl",
    pol: "pl",
    rus: "ru",
    ukr: "uk",
    ces: "cs",
    slk: "sk",
    hun: "hu",
    ron: "ro",
    bul: "bg",
    hrv: "hr",
    srp: "sr",
    slv: "sl",
    bos: "bs",
    mkd: "mk",
    sqi: "sq",
    ell: "el",
    tur: "tr",
    // Scandinavian languages
    swe: "sv",
    dan: "da",
    nor: "no",
    nob: "no", // Norwegian Bokmål
    nno: "no", // Norwegian Nynorsk
    fin: "fi",
    isl: "is",
    // Baltic languages
    lit: "lt",
    lav: "lv",
    est: "et",
    // Celtic languages
    gle: "ga",
    cym: "cy",
    gla: "gd",
    // Asian languages
    cmn: "zh", // Chinese Mandarin
    zho: "zh", // Chinese
    yue: "zh", // Cantonese (map to zh)
    jpn: "ja",
    kor: "ko",
    vie: "vi",
    tha: "th",
    ind: "id",
    msa: "ms", // Malay
    zlm: "ms", // Malay
    tgl: "tl", // Tagalog
    fil: "tl", // Filipino
    hin: "hi",
    ben: "bn",
    tam: "ta",
    tel: "te",
    mar: "mr",
    guj: "gu",
    kan: "kn",
    mal: "ml",
    pan: "pa",
    urd: "ur",
    nep: "ne",
    sin: "si",
    mya: "my",
    khm: "km",
    lao: "lo",
    mon: "mn",
    kat: "ka",
    hye: "hy",
    aze: "az",
    kaz: "kk",
    uzb: "uz",
    kir: "ky",
    tgk: "tg",
    tuk: "tk",
    // Middle Eastern languages
    arb: "ar", // Standard Arabic
    ara: "ar", // Arabic
    heb: "he",
    fas: "fa", // Persian
    pes: "fa", // Iranian Persian
    pus: "ps", // Pashto
    kur: "ku",
    kmr: "ku", // Kurdish Kurmanji
    // African languages
    swa: "sw",
    swh: "sw", // Swahili
    amh: "am",
    hau: "ha",
    ibo: "ig",
    yor: "yo",
    zul: "zu",
    xho: "xh",
    afr: "af",
    som: "so",
    mlg: "mg",
    nya: "ny",
    sna: "sn",
    kin: "rw",
    // Other European languages
    eus: "eu",
    cat: "ca",
    glg: "gl",
    mlt: "mt",
    ltz: "lb",
    bel: "be",
    // South American indigenous
    que: "qu",
    aym: "ay",
    grn: "gn",
    // Pacific languages
    mri: "mi",
    smo: "sm",
    haw: "haw",
    // South/Southeast Asian
    jav: "jw",
    sun: "su",
    ceb: "ceb",
    hmn: "hmn",
    // Constructed/Special
    epo: "eo",
    lat: "la",
    // Additional languages
    hat: "ht",
    yid: "yi",
    cos: "co",
    fry: "fy",
    snd: "sd",
    tat: "tt",
};

/**
 * Detect language from text using franc library
 *
 * @param text - Text to analyze
 * @param minLength - Minimum text length for reliable detection (default: 10)
 * @returns Language detection result
 */
export function detectLanguage(
    text: string,
    minLength: number = 10
): LanguageDetectionResult {
    // Default to English if text is too short
    if (!text || text.trim().length < minLength) {
        return {
            code: "en",
            confidence: 0,
            isSupported: true,
            rawCode: "und", // undetermined
        };
    }

    // Get all language probabilities
    const results = francAll(text, { minLength: 3 });

    if (results.length === 0 || results[0][0] === "und") {
        return {
            code: "en",
            confidence: 0,
            isSupported: true,
            rawCode: "und",
        };
    }

    // Get top result
    const [topCode, topScore] = results[0];

    // Convert ISO 639-3 to ISO 639-1
    const iso639_1 = ISO_639_3_TO_639_1[topCode] || topCode.substring(0, 2);

    // Check if supported
    const isSupported = isSupportedLanguage(iso639_1);

    // Calculate confidence based on score distribution
    // franc returns values that are not normalized, so we calculate relative confidence
    const totalScore = results.slice(0, 5).reduce((sum: number, [, score]: [string, number]) => sum + score, 0);
    const confidence = totalScore > 0 ? topScore / totalScore : 0;

    // Determine final code
    const finalCode: SupportedLanguage = isSupported
        ? (iso639_1 as SupportedLanguage)
        : "en"; // Fall back to English

    return {
        code: finalCode,
        confidence: Math.min(1, Math.max(0, confidence)),
        isSupported,
        rawCode: topCode,
    };
}

/**
 * Detect language from email subject and body with weighted combination
 *
 * @param subject - Email subject
 * @param body - Email body text
 * @param subjectWeight - Weight for subject (default: 0.3)
 * @returns Combined language detection result
 */
export function detectEmailLanguage(
    subject: string,
    body: string,
    subjectWeight: number = 0.3
): LanguageDetectionResult {
    const bodyWeight = 1 - subjectWeight;

    // Combine subject and body for detection
    // Body usually has more text and is more reliable
    const combinedText = `${subject} ${body}`.trim();

    // If combined text is short, use it directly
    if (combinedText.length < 50) {
        return detectLanguage(combinedText);
    }

    // Detect from both separately
    const subjectResult = detectLanguage(subject, 5);
    const bodyResult = detectLanguage(body, 10);

    // If body detection is confident, prefer it
    if (bodyResult.confidence > 0.7) {
        return bodyResult;
    }

    // If subject and body agree, high confidence
    if (subjectResult.code === bodyResult.code) {
        return {
            code: bodyResult.code,
            confidence: Math.max(subjectResult.confidence, bodyResult.confidence),
            isSupported: bodyResult.isSupported,
            rawCode: bodyResult.rawCode,
        };
    }

    // Weighted average - prefer body since it's usually longer
    const weightedSubjectConfidence = subjectResult.confidence * subjectWeight;
    const weightedBodyConfidence = bodyResult.confidence * bodyWeight;

    if (weightedBodyConfidence >= weightedSubjectConfidence) {
        return bodyResult;
    }

    return subjectResult;
}

/**
 * Get all detected languages with their confidence scores
 *
 * @param text - Text to analyze
 * @param limit - Maximum number of results (default: 5)
 * @returns Array of language detection results sorted by confidence
 */
export function detectLanguages(
    text: string,
    limit: number = 5
): LanguageDetectionResult[] {
    if (!text || text.trim().length < 10) {
        return [
            {
                code: "en",
                confidence: 0,
                isSupported: true,
                rawCode: "und",
            },
        ];
    }

    const results = francAll(text, { minLength: 3 });

    if (results.length === 0) {
        return [
            {
                code: "en",
                confidence: 0,
                isSupported: true,
                rawCode: "und",
            },
        ];
    }

    // Calculate total for normalization
    const totalScore = results.slice(0, limit).reduce((sum: number, [, score]: [string, number]) => sum + score, 0);

    return results.slice(0, limit).map(([code, score]: [string, number]) => {
        const iso639_1 = ISO_639_3_TO_639_1[code] || code.substring(0, 2);
        const isSupported = isSupportedLanguage(iso639_1);

        return {
            code: isSupported ? (iso639_1 as SupportedLanguage) : "en",
            confidence: totalScore > 0 ? score / totalScore : 0,
            isSupported,
            rawCode: code,
        };
    });
}
