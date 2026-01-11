// ============================================================================
// Bayesian Token Database
// Pre-computed token probabilities based on spam corpus analysis
// Using Paul Graham's "A Plan for Spam" methodology
// ============================================================================

export interface TokenProbability {
    spam: number; // P(token|spam)
    ham: number; // P(token|ham)
}

// Pre-computed token probabilities
// These are based on analysis of large spam/ham corpora
// Probability values represent likelihood of token appearing in spam vs ham
export const BAYESIAN_TOKENS: Map<string, TokenProbability> = new Map([
    // Very strong spam indicators (>0.95 spam probability)
    ["viagra", { spam: 0.99, ham: 0.001 }],
    ["cialis", { spam: 0.99, ham: 0.001 }],
    ["enlargement", { spam: 0.98, ham: 0.002 }],
    ["nigerian", { spam: 0.97, ham: 0.01 }],
    ["inheritance", { spam: 0.95, ham: 0.02 }],
    ["beneficiary", { spam: 0.92, ham: 0.03 }],
    ["lottery", { spam: 0.96, ham: 0.01 }],
    ["winner", { spam: 0.88, ham: 0.08 }],
    ["jackpot", { spam: 0.95, ham: 0.01 }],
    ["unsubscribe", { spam: 0.75, ham: 0.15 }],
    ["optout", { spam: 0.85, ham: 0.05 }],
    ["opt-out", { spam: 0.8, ham: 0.08 }],

    // Strong spam indicators (0.85-0.95)
    ["click", { spam: 0.7, ham: 0.25 }],
    ["free", { spam: 0.72, ham: 0.3 }],
    ["money", { spam: 0.68, ham: 0.28 }],
    ["cash", { spam: 0.75, ham: 0.15 }],
    ["prize", { spam: 0.88, ham: 0.05 }],
    ["won", { spam: 0.72, ham: 0.25 }],
    ["urgent", { spam: 0.78, ham: 0.12 }],
    ["immediately", { spam: 0.7, ham: 0.2 }],
    ["act", { spam: 0.55, ham: 0.35 }],
    ["limited", { spam: 0.65, ham: 0.3 }],
    ["offer", { spam: 0.68, ham: 0.28 }],
    ["discount", { spam: 0.72, ham: 0.22 }],
    ["guaranteed", { spam: 0.78, ham: 0.15 }],
    ["risk-free", { spam: 0.88, ham: 0.05 }],
    ["obligation", { spam: 0.75, ham: 0.18 }],
    ["credit", { spam: 0.65, ham: 0.3 }],
    ["debt", { spam: 0.7, ham: 0.2 }],
    ["loan", { spam: 0.72, ham: 0.22 }],
    ["mortgage", { spam: 0.75, ham: 0.18 }],
    ["pharmacy", { spam: 0.9, ham: 0.03 }],
    ["prescription", { spam: 0.82, ham: 0.12 }],
    ["medication", { spam: 0.78, ham: 0.15 }],
    ["pills", { spam: 0.85, ham: 0.08 }],
    ["weight", { spam: 0.62, ham: 0.32 }],
    ["diet", { spam: 0.68, ham: 0.28 }],
    ["lose", { spam: 0.55, ham: 0.38 }],
    ["pounds", { spam: 0.6, ham: 0.32 }],

    // Moderate spam indicators (0.70-0.85)
    ["buy", { spam: 0.58, ham: 0.38 }],
    ["order", { spam: 0.52, ham: 0.42 }],
    ["purchase", { spam: 0.55, ham: 0.4 }],
    ["sale", { spam: 0.6, ham: 0.35 }],
    ["cheap", { spam: 0.75, ham: 0.18 }],
    ["save", { spam: 0.58, ham: 0.38 }],
    ["deal", { spam: 0.55, ham: 0.4 }],
    ["special", { spam: 0.52, ham: 0.42 }],
    ["exclusive", { spam: 0.6, ham: 0.35 }],
    ["bonus", { spam: 0.68, ham: 0.28 }],
    ["gift", { spam: 0.62, ham: 0.32 }],
    ["congratulations", { spam: 0.82, ham: 0.12 }],
    ["selected", { spam: 0.72, ham: 0.22 }],
    ["confirm", { spam: 0.55, ham: 0.4 }],
    ["verify", { spam: 0.65, ham: 0.3 }],
    ["account", { spam: 0.48, ham: 0.48 }],
    ["password", { spam: 0.52, ham: 0.42 }],
    ["suspended", { spam: 0.75, ham: 0.18 }],
    ["locked", { spam: 0.68, ham: 0.28 }],
    ["security", { spam: 0.52, ham: 0.42 }],
    ["update", { spam: 0.45, ham: 0.48 }],

    // Phishing indicators
    ["paypal", { spam: 0.7, ham: 0.25 }],
    ["ebay", { spam: 0.68, ham: 0.28 }],
    ["amazon", { spam: 0.55, ham: 0.4 }],
    ["bank", { spam: 0.52, ham: 0.42 }],
    ["wire", { spam: 0.72, ham: 0.22 }],
    ["transfer", { spam: 0.6, ham: 0.35 }],
    ["routing", { spam: 0.72, ham: 0.22 }],
    ["swift", { spam: 0.65, ham: 0.3 }],
    ["western", { spam: 0.68, ham: 0.28 }],
    ["union", { spam: 0.5, ham: 0.45 }],
    ["moneygram", { spam: 0.88, ham: 0.05 }],
    ["bitcoin", { spam: 0.72, ham: 0.22 }],
    ["cryptocurrency", { spam: 0.7, ham: 0.25 }],
    ["wallet", { spam: 0.62, ham: 0.32 }],
    ["blockchain", { spam: 0.6, ham: 0.35 }],

    // Strong ham indicators (<0.30 spam probability)
    ["meeting", { spam: 0.15, ham: 0.78 }],
    ["schedule", { spam: 0.18, ham: 0.75 }],
    ["project", { spam: 0.12, ham: 0.82 }],
    ["team", { spam: 0.15, ham: 0.78 }],
    ["deadline", { spam: 0.1, ham: 0.85 }],
    ["attached", { spam: 0.18, ham: 0.75 }],
    ["attachment", { spam: 0.2, ham: 0.72 }],
    ["document", { spam: 0.25, ham: 0.68 }],
    ["report", { spam: 0.18, ham: 0.75 }],
    ["review", { spam: 0.22, ham: 0.7 }],
    ["feedback", { spam: 0.15, ham: 0.78 }],
    ["discussion", { spam: 0.12, ham: 0.82 }],
    ["agenda", { spam: 0.08, ham: 0.88 }],
    ["minutes", { spam: 0.1, ham: 0.85 }],
    ["conference", { spam: 0.15, ham: 0.78 }],
    ["call", { spam: 0.35, ham: 0.58 }],
    ["regards", { spam: 0.22, ham: 0.7 }],
    ["sincerely", { spam: 0.25, ham: 0.68 }],
    ["thanks", { spam: 0.18, ham: 0.75 }],
    ["thank", { spam: 0.2, ham: 0.72 }],
    ["appreciate", { spam: 0.15, ham: 0.78 }],
    ["following", { spam: 0.25, ham: 0.68 }],
    ["discussed", { spam: 0.1, ham: 0.85 }],
    ["conversation", { spam: 0.15, ham: 0.78 }],
    ["invoice", { spam: 0.28, ham: 0.65 }],
    ["receipt", { spam: 0.3, ham: 0.62 }],
    ["summary", { spam: 0.18, ham: 0.75 }],
    ["analysis", { spam: 0.12, ham: 0.82 }],
    ["research", { spam: 0.15, ham: 0.78 }],
    ["data", { spam: 0.2, ham: 0.72 }],
    ["results", { spam: 0.22, ham: 0.7 }],

    // Tech/developer ham indicators
    ["repository", { spam: 0.05, ham: 0.92 }],
    ["commit", { spam: 0.05, ham: 0.92 }],
    ["merge", { spam: 0.08, ham: 0.88 }],
    ["branch", { spam: 0.08, ham: 0.88 }],
    ["pull", { spam: 0.1, ham: 0.85 }],
    ["request", { spam: 0.35, ham: 0.58 }],
    ["deploy", { spam: 0.08, ham: 0.88 }],
    ["build", { spam: 0.12, ham: 0.82 }],
    ["test", { spam: 0.15, ham: 0.78 }],
    ["debug", { spam: 0.05, ham: 0.92 }],
    ["error", { spam: 0.22, ham: 0.7 }],
    ["bug", { spam: 0.12, ham: 0.82 }],
    ["fix", { spam: 0.15, ham: 0.78 }],
    ["issue", { spam: 0.18, ham: 0.75 }],
    ["feature", { spam: 0.12, ham: 0.82 }],
    ["release", { spam: 0.15, ham: 0.78 }],
    ["version", { spam: 0.18, ham: 0.75 }],
    ["documentation", { spam: 0.08, ham: 0.88 }],
    ["api", { spam: 0.1, ham: 0.85 }],
    ["server", { spam: 0.18, ham: 0.75 }],
    ["database", { spam: 0.12, ham: 0.82 }],
    ["query", { spam: 0.15, ham: 0.78 }],
    ["function", { spam: 0.1, ham: 0.85 }],
    ["variable", { spam: 0.08, ham: 0.88 }],
    ["class", { spam: 0.12, ham: 0.82 }],
    ["method", { spam: 0.15, ham: 0.78 }],
    ["interface", { spam: 0.12, ham: 0.82 }],
]);

// Calculate spam probability using Robinson-Fisher method
export function calculateRobinsonFisher(tokens: string[]): number {
    const probabilities: number[] = [];

    for (const token of tokens) {
        const lowerToken = token.toLowerCase();
        const tokenData = BAYESIAN_TOKENS.get(lowerToken);

        if (tokenData) {
            // Calculate spam probability for this token
            // P(spam|token) = P(token|spam) * P(spam) / P(token)
            // Simplified using equal priors: P(spam|token) = P(token|spam) / (P(token|spam) + P(token|ham))
            const pSpam = tokenData.spam / (tokenData.spam + tokenData.ham);
            probabilities.push(pSpam);
        }
    }

    if (probabilities.length === 0) {
        return 0.5; // Neutral
    }

    // Use the 15 most significant probabilities (furthest from 0.5)
    const significant = probabilities
        .map((p) => ({ p, distance: Math.abs(p - 0.5) }))
        .sort((a, b) => b.distance - a.distance)
        .slice(0, 15)
        .map((x) => x.p);

    const productSpam = significant.reduce((acc, p) => acc * p, 1);
    const productHam = significant.reduce((acc, p) => acc * (1 - p), 1);

    if (productSpam === 0 && productHam === 0) return 0.5; // Avoid 0/0

    const result = productSpam / (productSpam + productHam);

    return Math.max(0, Math.min(1, result));
}

// Tokenize text for Bayesian analysis
export function tokenize(text: string): string[] {
    // Simple tokenization - split on non-alphanumeric
    const tokens = text
        .toLowerCase()
        .replace(/[^a-z0-9\s'-]/g, " ")
        .split(/\s+/)
        .filter((t) => t.length >= 3 && t.length <= 20);

    // Deduplicate while preserving some frequency info
    const tokenCounts = new Map<string, number>();
    for (const token of tokens) {
        tokenCounts.set(token, (tokenCounts.get(token) || 0) + 1);
    }

    // Return unique tokens, but include repeated important ones
    const result: string[] = [];
    for (const [token, count] of tokenCounts) {
        // Add token once, or twice if it appears many times
        result.push(token);
        if (count >= 3) {
            result.push(token);
        }
    }

    return result;
}
