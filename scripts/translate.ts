#!/usr/bin/env bun
// ============================================================================
// Translation Script for Multilingual Spam Detection
// Translates English spam detection dataset to multiple languages using
// Google Translate API
// ============================================================================

import { parseArgs } from "util";
import { readFile, writeFile, mkdir } from "fs/promises";
import { existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

// Types
interface SpamWord {
    word: string;
    score: number;
    category: string;
    caseSensitive?: boolean;
}

interface SpamSubjectPattern {
    pattern: string;
    score: number;
    name: string;
}

interface TokenProbability {
    spam: number;
    ham: number;
}

interface LanguageDataset {
    language: string;
    languageName: string;
    spamWords: SpamWord[];
    spamSingleWords: Record<string, number>;
    spamSubjectPatterns: SpamSubjectPattern[];
    hamWords: Record<string, number>;
    bayesianTokens: Record<string, TokenProbability>;
    urgencyWords: string[];
    greetingWords: string[];
    genericGreetings: string[];
}

// Supported languages with their ISO 639-1 codes and names
// Comprehensive list of 100+ languages supported by Google Translate
const LANGUAGES: Record<string, string> = {
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

// Get script directory
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const LANGUAGES_DIR = join(__dirname, "..", "src", "data", "languages");

// Parse command line arguments
const { values } = parseArgs({
    args: process.argv.slice(2),
    options: {
        "api-key": {
            type: "string",
            short: "k",
        },
        languages: {
            type: "string",
            short: "l",
        },
        help: {
            type: "boolean",
            short: "h",
        },
        dry: {
            type: "boolean",
            short: "d",
        },
    },
});

function printHelp(): void {
    console.log(`
Translation Script for SpamGuard Multilingual Support

Usage: bun run translate.ts --api-key YOUR_API_KEY [options]

Options:
  -k, --api-key <key>     Google Translate API key (required)
  -l, --languages <list>  Comma-separated language codes (default: all)
                          Available: ${Object.keys(LANGUAGES).join(", ")}
  -d, --dry               Dry run - show what would be translated without API calls
  -h, --help              Show this help message

Examples:
  bun run translate.ts --api-key YOUR_KEY
  bun run translate.ts --api-key YOUR_KEY --languages es,fr,de
  bun run translate.ts --dry
`);
}

if (values.help) {
    printHelp();
    process.exit(0);
}

const apiKey = values["api-key"];
const isDryRun = values.dry ?? false;

if (!apiKey && !isDryRun) {
    console.error("Error: --api-key is required (or use --dry for dry run)");
    printHelp();
    process.exit(1);
}

// Parse target languages
let targetLanguages: string[];
if (values.languages) {
    targetLanguages = values.languages.split(",").map((l) => l.trim().toLowerCase());
    // Validate languages
    for (const lang of targetLanguages) {
        if (!LANGUAGES[lang]) {
            console.error(`Error: Unknown language code "${lang}"`);
            console.error(`Available: ${Object.keys(LANGUAGES).join(", ")}`);
            process.exit(1);
        }
    }
} else {
    targetLanguages = Object.keys(LANGUAGES);
}

console.log(`\nSpamGuard Translation Script`);
console.log(`============================`);
console.log(`Target languages: ${targetLanguages.map((l) => `${l} (${LANGUAGES[l]})`).join(", ")}`);
console.log(`Dry run: ${isDryRun ? "yes" : "no"}\n`);

// Google Translate API
async function translateText(text: string, targetLang: string): Promise<string> {
    if (isDryRun) {
        return `[${targetLang}] ${text}`;
    }

    const url = `https://translation.googleapis.com/language/translate/v2?key=${apiKey}`;

    const response = await fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            q: text,
            source: "en",
            target: targetLang,
            format: "text",
        }),
    });

    if (!response.ok) {
        const error = await response.text();
        throw new Error(`Translation API error: ${response.status} - ${error}`);
    }

    const data = (await response.json()) as {
        data: { translations: { translatedText: string }[] };
    };

    return data.data.translations[0].translatedText;
}

// Batch translate to minimize API calls
async function translateBatch(texts: string[], targetLang: string): Promise<string[]> {
    if (texts.length === 0) return [];

    if (isDryRun) {
        return texts.map((t) => `[${targetLang}] ${t}`);
    }

    // Google Translate API supports batching up to 128 texts
    const BATCH_SIZE = 100;
    const results: string[] = [];

    for (let i = 0; i < texts.length; i += BATCH_SIZE) {
        const batch = texts.slice(i, i + BATCH_SIZE);

        const url = `https://translation.googleapis.com/language/translate/v2?key=${apiKey}`;

        const response = await fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                q: batch,
                source: "en",
                target: targetLang,
                format: "text",
            }),
        });

        if (!response.ok) {
            const error = await response.text();
            throw new Error(`Translation API error: ${response.status} - ${error}`);
        }

        const data = (await response.json()) as {
            data: { translations: { translatedText: string }[] };
        };

        results.push(...data.data.translations.map((t) => t.translatedText));

        // Rate limiting - wait a bit between batches
        if (i + BATCH_SIZE < texts.length) {
            await new Promise((resolve) => setTimeout(resolve, 100));
        }
    }

    return results;
}

// Load English dataset
async function loadEnglishDataset(): Promise<LanguageDataset> {
    const enPath = join(LANGUAGES_DIR, "en.json");
    const content = await readFile(enPath, "utf-8");
    return JSON.parse(content) as LanguageDataset;
}

// Translate dataset to a target language
async function translateDataset(
    enDataset: LanguageDataset,
    targetLang: string
): Promise<LanguageDataset> {
    console.log(`\nTranslating to ${LANGUAGES[targetLang]} (${targetLang})...`);

    // Collect all texts to translate
    const spamWordTexts = enDataset.spamWords.map((w) => w.word);
    const hamWordTexts = Object.keys(enDataset.hamWords);
    const bayesianTokenTexts = Object.keys(enDataset.bayesianTokens);
    const urgencyWordTexts = enDataset.urgencyWords;
    const greetingWordTexts = enDataset.greetingWords;
    const genericGreetingTexts = enDataset.genericGreetings;

    console.log(`  - Spam words: ${spamWordTexts.length}`);
    console.log(`  - Ham words: ${hamWordTexts.length}`);
    console.log(`  - Bayesian tokens: ${bayesianTokenTexts.length}`);
    console.log(`  - Urgency words: ${urgencyWordTexts.length}`);
    console.log(`  - Greeting words: ${greetingWordTexts.length}`);
    console.log(`  - Generic greetings: ${genericGreetingTexts.length}`);

    // Combine all for batch translation
    const allTexts = [
        ...spamWordTexts,
        ...hamWordTexts,
        ...bayesianTokenTexts,
        ...urgencyWordTexts,
        ...greetingWordTexts,
        ...genericGreetingTexts,
    ];

    console.log(`  - Total texts to translate: ${allTexts.length}`);

    // Translate all at once
    const translatedTexts = await translateBatch(allTexts, targetLang);

    // Split back into categories
    let idx = 0;

    // Spam words
    const translatedSpamWords: SpamWord[] = enDataset.spamWords.map((w, i) => ({
        word: translatedTexts[idx + i].toLowerCase(),
        score: w.score,
        category: w.category,
        ...(w.caseSensitive !== undefined && { caseSensitive: w.caseSensitive }),
    }));
    idx += spamWordTexts.length;

    // Ham words
    const translatedHamWords: Record<string, number> = {};
    const hamWordEntries = Object.entries(enDataset.hamWords);
    for (let i = 0; i < hamWordEntries.length; i++) {
        const translatedKey = translatedTexts[idx + i].toLowerCase();
        translatedHamWords[translatedKey] = hamWordEntries[i][1];
    }
    idx += hamWordTexts.length;

    // Bayesian tokens
    const translatedBayesianTokens: Record<string, TokenProbability> = {};
    const bayesianEntries = Object.entries(enDataset.bayesianTokens);
    for (let i = 0; i < bayesianEntries.length; i++) {
        const translatedKey = translatedTexts[idx + i].toLowerCase();
        translatedBayesianTokens[translatedKey] = bayesianEntries[i][1];
    }
    idx += bayesianTokenTexts.length;

    // Urgency words
    const translatedUrgencyWords = translatedTexts
        .slice(idx, idx + urgencyWordTexts.length)
        .map((t) => t.toLowerCase());
    idx += urgencyWordTexts.length;

    // Greeting words
    const translatedGreetingWords = translatedTexts
        .slice(idx, idx + greetingWordTexts.length)
        .map((t) => t.toLowerCase());
    idx += greetingWordTexts.length;

    // Generic greetings
    const translatedGenericGreetings = translatedTexts
        .slice(idx, idx + genericGreetingTexts.length)
        .map((t) => t.toLowerCase());

    // Build translated dataset
    const translatedDataset: LanguageDataset = {
        language: targetLang,
        languageName: LANGUAGES[targetLang],
        spamWords: translatedSpamWords,
        // Keep spam single words as-is (they are obfuscated English like "v1agra")
        spamSingleWords: enDataset.spamSingleWords,
        // Keep subject patterns as-is (they use regex that works across languages)
        spamSubjectPatterns: enDataset.spamSubjectPatterns,
        hamWords: translatedHamWords,
        bayesianTokens: translatedBayesianTokens,
        urgencyWords: translatedUrgencyWords,
        greetingWords: translatedGreetingWords,
        genericGreetings: translatedGenericGreetings,
    };

    console.log(`  Done!`);

    return translatedDataset;
}

// Main execution
async function main(): Promise<void> {
    try {
        // Ensure languages directory exists
        if (!existsSync(LANGUAGES_DIR)) {
            await mkdir(LANGUAGES_DIR, { recursive: true });
        }

        // Load English dataset
        console.log("Loading English dataset...");
        const enDataset = await loadEnglishDataset();
        console.log(`Loaded ${enDataset.spamWords.length} spam words, ${Object.keys(enDataset.hamWords).length} ham words`);

        // Translate to each target language
        for (const lang of targetLanguages) {
            try {
                const translatedDataset = await translateDataset(enDataset, lang);

                // Save to file
                const outputPath = join(LANGUAGES_DIR, `${lang}.json`);
                await writeFile(outputPath, JSON.stringify(translatedDataset, null, 4), "utf-8");
                console.log(`  Saved to: ${outputPath}`);
            } catch (error) {
                console.error(`  Error translating to ${lang}:`, error);
                if (!isDryRun) {
                    throw error;
                }
            }
        }

        console.log(`\nTranslation complete!`);
        console.log(`Generated ${targetLanguages.length} language files in ${LANGUAGES_DIR}`);
    } catch (error) {
        console.error("\nFatal error:", error);
        process.exit(1);
    }
}

main();
