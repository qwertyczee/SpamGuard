# SpamGuard

A high-accuracy, stateless spam detection service running on Cloudflare Workers. Inspired by Rspamd, but designed to run entirely at the edge without databases or external dependencies.

## Features

- **Multi-layer Analysis**: 6 independent analyzers work together for accurate detection
- **Stateless Design**: No database required - runs entirely in a Cloudflare Worker
- **Fast**: Typical analysis completes in <50ms
- **Accurate**: >90% spam detection with <10% false positives
- **Configurable**: Adjustable thresholds and debug options
- **Batch Support**: Analyze up to 100 emails in one request

## Detection Layers

1. **Header Analyzer** - SPF/DKIM/DMARC validation, header anomalies, authentication failures
2. **Content Analyzer** - Spam phrases, word patterns, text statistics
3. **URL Analyzer** - Suspicious domains, URL shorteners, phishing patterns
4. **HTML Analyzer** - Hidden text, tracking pixels, malicious elements
5. **Pattern Analyzer** - Obfuscation detection, encoding tricks, structural patterns
6. **Bayesian Classifier** - Statistical token analysis using pre-trained probabilities

## Installation

```bash
npm install
```

## Development

```bash
# Run development server
npm run dev

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Type check
npm run typecheck
```

## Deployment

```bash
npm run deploy
```

## API Endpoints

### `GET /`

Returns API information and available endpoints.

### `GET /health`

Health check endpoint.

### `GET /config`

Returns default configuration values.

### `POST /analyze`

Full spam analysis with detailed results.

**Request:**

```json
{
    "from": "sender@example.com",
    "to": "recipient@example.com",
    "subject": "Email Subject",
    "textBody": "Plain text content",
    "htmlBody": "<html>HTML content</html>",
    "headers": {
        "received-spf": "pass",
        "dkim-signature": "..."
    },
    "debug": true
}
```

**Response:**

```json
{
  "isSpam": false,
  "score": 2.5,
  "threshold": 5.0,
  "confidence": 0.85,
  "classification": "probable_ham",
  "analyzers": [...],
  "topReasons": [...],
  "processingTimeMs": 12.5,
  "debug": {...}
}
```

### `POST /check`

Quick spam check - returns only true/false.

**Request:**

```json
{
    "subject": "Test",
    "textBody": "Content"
}
```

**Response:**

```json
{
    "isSpam": false
}
```

### `POST /score`

Returns score and classification only.

**Response:**

```json
{
    "score": 2.5,
    "threshold": 5.0,
    "classification": "probable_ham"
}
```

### `POST /batch`

Analyze multiple emails (max 100).

**Request:**

```json
{
    "emails": [
        { "subject": "Email 1", "textBody": "..." },
        { "subject": "Email 2", "textBody": "..." }
    ],
    "config": {
        "spamThreshold": 5.0
    }
}
```

**Response:**

```json
{
  "summary": {
    "total": 2,
    "spam": 1,
    "ham": 1,
    "errors": 0
  },
  "results": [...]
}
```

### `POST /analyze/raw`

Analyze raw MIME email.

**Request:**

```
Content-Type: text/plain

From: sender@example.com
To: recipient@example.com
Subject: Test

Body content here.
```

## Configuration

| Option                  | Default | Description                               |
| ----------------------- | ------- | ----------------------------------------- |
| `spamThreshold`         | 5.0     | Score above which email is marked as spam |
| `probableSpamThreshold` | 3.0     | Score for "probable spam" classification  |
| `enableDebug`           | false   | Include debug information in response     |

## Classifications

- **ham** - Score ≤ 1.0, definitely legitimate
- **probable_ham** - Score 1.0-3.0, likely legitimate
- **probable_spam** - Score 3.0-5.0, likely spam
- **spam** - Score ≥ 5.0, definitely spam

## Usage Examples

### cURL

```bash
# Quick check
curl -X POST https://your-worker.workers.dev/check \
  -H "Content-Type: application/json" \
  -d '{"subject": "Test", "textBody": "Hello world"}'

# Full analysis
curl -X POST https://your-worker.workers.dev/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "from": "sender@example.com",
    "to": "recipient@example.com",
    "subject": "Important Message",
    "textBody": "This is the email content",
    "debug": true
  }'
```

### JavaScript

```javascript
const response = await fetch("https://your-worker.workers.dev/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
        from: "sender@example.com",
        subject: "Test Email",
        textBody: "Email content here",
    }),
});

const result = await response.json();
console.log(`Spam: ${result.isSpam}, Score: ${result.score}`);
```

## Project Structure

```
spamguard/
├── src/
│   ├── index.ts           # Hono API entry point
│   ├── engine.ts          # Main SpamGuard engine
│   ├── types.ts           # TypeScript types
│   ├── analyzers/
│   │   ├── header.ts      # Header analysis
│   │   ├── content.ts     # Content analysis
│   │   ├── url.ts         # URL analysis
│   │   ├── html.ts        # HTML analysis
│   │   ├── pattern.ts     # Pattern detection
│   │   └── bayesian.ts    # Bayesian classifier
│   ├── data/
│   │   ├── spam-words.ts  # Spam word database
│   │   ├── url-blacklist.ts # URL/domain data
│   │   ├── patterns.ts    # Detection patterns
│   │   └── bayesian-tokens.ts # Token probabilities
│   ├── parser/
│   │   └── email.ts       # Email parser
│   └── utils/
│       └── text.ts        # Text utilities
├── tests/
│   ├── fixtures/
│   │   └── emails.ts      # Test email samples
│   ├── unit/
│   │   ├── parser.test.ts
│   │   ├── text.test.ts
│   │   └── analyzers.test.ts
│   └── integration/
│       ├── engine.test.ts
│       └── api.test.ts
├── package.json
├── tsconfig.json
└── wrangler.toml
```

## License

MIT
