// ============================================================================
// URL Analysis Data
// Suspicious TLDs, URL shorteners, known spam domains
// ============================================================================

// Suspicious or frequently abused TLDs
export const SUSPICIOUS_TLDS = new Set([
    // High risk TLDs often used by spammers
    "zip",
    "mov",
    "top",
    "xyz",
    "work",
    "click",
    "link",
    "gq",
    "ml",
    "cf",
    "ga",
    "tk",
    "buzz",
    "icu",
    "best",
    "monster",
    "rest",
    "cyou",
    "cfd",
    "sbs",
    "quest",
    "cam",
    "bond",
    "bid",
    "trade",
    "review",
    "party",
    "download",
    "racing",
    "win",
    "loan",
    "cricket",
    "science",
    "date",
    "faith",
    "accountant",
    "stream",
    "gdn",
    "men",
    "webcam",
    "adult",
    "porn",
    "xxx",
    "sex",

    // Country TLDs often abused (but also legitimate)
    "ru",
    "cn",
    "cc",
    "su",
    "pw",
]);

// URL shortener domains
export const URL_SHORTENERS = new Set([
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "j.mp",
    "adf.ly",
    "cur.lv",
    "tiny.cc",
    "shorte.st",
    "bc.vc",
    "v.gd",
    "po.st",
    "u.to",
    "cutt.ly",
    "shorturl.at",
    "rb.gy",
    "t.ly",
    "rebrand.ly",
    "clck.ru",
    "shorturl.asia",
    "mcaf.ee",
    "su.pr",
    "clicky.me",
    "budurl.com",
    "soo.gd",
    "x.co",
    "yourls.org",
    "urlz.fr",
    "qr.net",
    "url.ie",
    "zpr.io",
]);

// Known phishing/spam domain patterns
export const SPAM_DOMAIN_PATTERNS: Array<{
    pattern: RegExp;
    score: number;
    name: string;
}> = [
    // Typosquatting patterns for major brands
    { pattern: /paypa[l1].*\.(com|net|org)/i, score: 2.5, name: "PAYPAL_TYPO" },
    { pattern: /app[l1]e.*\.(com|net)/i, score: 2.0, name: "APPLE_TYPO" },
    { pattern: /amaz[o0]n.*\.(com|net)/i, score: 2.0, name: "AMAZON_TYPO" },
    {
        pattern: /g[o0][o0]g[l1]e.*\.(com|net)/i,
        score: 2.0,
        name: "GOOGLE_TYPO",
    },
    {
        pattern: /micr[o0]s[o0]ft.*\.(com|net)/i,
        score: 2.0,
        name: "MICROSOFT_TYPO",
    },
    {
        pattern: /faceb[o0][o0]k.*\.(com|net)/i,
        score: 2.0,
        name: "FACEBOOK_TYPO",
    },
    { pattern: /netf[l1]ix.*\.(com|net)/i, score: 2.0, name: "NETFLIX_TYPO" },

    // Suspicious subdomains
    {
        pattern: /^(secure|login|account|verify|update|confirm|auth)[-.]/,
        score: 1.5,
        name: "PHISHY_SUBDOMAIN",
    },
    {
        pattern: /\.(secure|login|account|verify)\./,
        score: 1.8,
        name: "PHISHY_SUBDOMAIN_MID",
    },

    // Suspicious domain patterns
    {
        pattern: /-secure|-login|-verify|-confirm|-update/i,
        score: 1.5,
        name: "PHISHY_KEYWORD_DASH",
    },
    { pattern: /\d{4,}/, score: 0.8, name: "MANY_DIGITS" },
    { pattern: /[a-z]{20,}/, score: 1.0, name: "VERY_LONG_DOMAIN" },

    // Free hosting often abused
    {
        pattern:
            /\.(000webhostapp|herokuapp|netlify\.app|vercel\.app|github\.io|gitlab\.io)$/i,
        score: 0.5,
        name: "FREE_HOSTING",
    },
    {
        pattern: /\.(blogspot|wordpress|wix|weebly)\.com$/i,
        score: 0.3,
        name: "FREE_BLOG",
    },
];

// IP address URL detection
export const IP_URL_PATTERN = /^https?:\/\/(\d{1,3}\.){3}\d{1,3}/;

// Suspicious URL path patterns
export const SUSPICIOUS_PATH_PATTERNS: Array<{
    pattern: RegExp;
    score: number;
    name: string;
}> = [
    {
        pattern: /\.(exe|scr|bat|cmd|msi|jar|vbs|ps1|sh)(\?|$)/i,
        score: 2.5,
        name: "EXECUTABLE_EXTENSION",
    },
    {
        pattern: /\.(zip|rar|7z|tar|gz)(\?|$)/i,
        score: 1.0,
        name: "ARCHIVE_EXTENSION",
    },
    { pattern: /\.php\?.*=/i, score: 0.8, name: "PHP_WITH_PARAMS" },
    {
        pattern: /\/wp-(admin|includes|content)\/(?!themes|plugins)/i,
        score: 1.5,
        name: "WORDPRESS_EXPLOIT_PATH",
    },
    {
        pattern: /\/(admin|login|signin|verify|secure|account)\.php/i,
        score: 1.2,
        name: "PHISHY_PHP",
    },
    { pattern: /%[0-9a-f]{2}%[0-9a-f]{2}/i, score: 1.0, name: "ENCODED_CHARS" },
    { pattern: /[\x00-\x1f]/, score: 2.0, name: "CONTROL_CHARS" },
    { pattern: /\/\/+/, score: 1.0, name: "DOUBLE_SLASH" },
];

// Common legitimate domains (whitelist for reducing false positives)
export const LEGITIMATE_DOMAINS = new Set([
    "google.com",
    "gmail.com",
    "youtube.com",
    "facebook.com",
    "twitter.com",
    "instagram.com",
    "linkedin.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "stackoverflow.com",
    "wikipedia.org",
    "reddit.com",
    "dropbox.com",
    "slack.com",
    "zoom.us",
    "paypal.com",
    "stripe.com",
    "shopify.com",
    "salesforce.com",
    "cloudflare.com",
    "aws.amazon.com",
    "azure.microsoft.com",
]);

// Get root domain from full domain
export function getRootDomain(domain: string): string {
    const parts = domain.toLowerCase().split(".");
    if (parts.length <= 2) return domain.toLowerCase();

    // Handle co.uk, com.au, etc.
    const tld = parts.slice(-2).join(".");
    const commonCompoundTlds = [
        "co.uk",
        "com.au",
        "co.nz",
        "co.jp",
        "com.br",
        "co.in",
    ];

    if (commonCompoundTlds.includes(tld) && parts.length > 2) {
        return parts.slice(-3).join(".");
    }

    return parts.slice(-2).join(".");
}

// Extract TLD from domain
export function getTld(domain: string): string {
    const parts = domain.toLowerCase().split(".");
    return parts[parts.length - 1];
}
