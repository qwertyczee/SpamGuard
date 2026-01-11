# SpamGuard

A high-performance, stateless spam detection service running on Cloudflare Workers. Inspired by Rspamd, but designed to run entirely at the edge without databases or external dependencies.

**Current Performance (Enron Spam Dataset):**
*   **Spam Detection Rate:** 70.92%
*   **False Positive Rate:** 2.67%

> **Note:** The project history and logs may not reflect the most recent algorithmic adjustments and tuning represented in these statistics.

## Features

- **Multi-layer Analysis**: 6 independent analyzers work together for accurate detection
- **Stateless Design**: No database required - runs entirely in a Cloudflare Worker
- **Fast**: Typical analysis completes in <4ms
- **Accurate**: Tuned for low false positives suitable for business environments
- **Configurable**: Adjustable thresholds and debug options
- **Batch Support**: Analyze up to 100 emails in one request

## Detection Layers

1.  **Header Analyzer** - SPF/DKIM/DMARC validation, header anomalies, authentication failures
2.  **Content Analyzer** - Spam phrases, word patterns, text statistics
3.  **URL Analyzer** - Suspicious domains, URL shorteners, phishing patterns
4.  **HTML Analyzer** - Hidden text, tracking pixels, malicious elements
5.  **Pattern Analyzer** - Obfuscation detection, encoding tricks, structural patterns
6.  **Bayesian Classifier** - Statistical token analysis using pre-trained probabilities

## Installation

```bash
bun install
```

## Development

```bash
# Run development server
bun run dev

# Run tests
bun test

# Run tests with coverage
bun run test:coverage

# Type check
bun run typecheck
```

## Deployment

```bash
bun run deploy
```

## API Endpoints

### `GET /`
Returns API information and available endpoints.

### `GET /health`
Returns service health status and timestamp.

### `GET /config`
Returns the current default configuration values.

### `POST /analyze`
Performs full spam analysis and returns detailed results including individual analyzer scores and matched rules.

**Request Body Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `from` | string | Sender email address |
| `to` | string/array | Recipient email address(es) |
| `subject` | string | Email subject line |
| `textBody` (or `text_body`, `text`, `body`) | string | Plain text body content |
| `htmlBody` (or `html_body`, `html`) | string | HTML body content |
| `raw` | string | Raw MIME email string |
| `headers` | object | Key-value pairs of email headers |
| `receivedSpf` (or `received_spf`) | string | value of Received-SPF header |
| `dkimSignature` (or `dkim_signature`) | string | value of DKIM-Signature header |
| `authenticationResults` (or `authentication_results`) | string | value of Authentication-Results header |
| `clientIp` (or `client_ip`) | string | IP address of the sender |
| `helo` | string | HELO/EHLO string from SMTP session |
| `debug` | boolean | Set to `true` to include detailed debug info |
| `config` | object | Override default configuration (see Configuration section) |

**Example Request:**
```json
{
    "from": "sender@example.com",
    "to": "recipient@example.com",
    "subject": "Email Subject",
    "textBody": "Plain text content",
    "headers": {
        "received-spf": "pass"
    },
    "debug": true
}
```

**Example Response:**
```json
{
    "score": 0.2,
    "threshold": 3.5,
    "confidence": 0.37,
    "classification": "ham",
    "analyzers": [...],
    "topReasons": ["..."],
    "processingTimeMs": 1,
    "debug": {...}
}
```

### `POST /check`
Quick spam check returning a simple boolean verdict. Uses the same input parameters as `/analyze`.

**Response:**
```json
{
    "isSpam": false
}
```

### `POST /score`
Returns only the calculated score, threshold, and classification. Uses the same input parameters as `/analyze`.

**Response:**
```json
{
    "score": 2.5,
    "threshold": 3.5,
    "classification": "probable_ham"
}
```

### `POST /batch`
Analyze multiple emails in a single request (maximum 100).

**Request:**
```json
{
    "emails": [
        { "subject": "Email 1", "textBody": "..." },
        { "subject": "Email 2", "textBody": "..." }
    ],
    "config": {
        "spamThreshold": 4.0
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
Analyze a raw MIME email string.

**Option 1: JSON**
```json
{
    "raw": "From: sender@example.com\r\nSubject: Test\r\n\r\nBody..."
}
```

**Option 2: Text/Plain**
Send the raw email content directly as the request body with `Content-Type: text/plain` or `message/rfc822`.

## Configuration

These values can be passed in the `config` object to override defaults.

| Option | Default | Description |
|--------|---------|-------------|
| `spamThreshold` | 3.5 | Score above which email is marked as spam |
| `probableSpamThreshold` | 2.0 | Score for "probable spam" classification |
| `enableDebug` | false | Include debug information in response |

## Classifications

- **ham** - Score ≤ 1.0, definitely legitimate
- **probable_ham** - Score 1.0-2.0, likely legitimate
- **probable_spam** - Score 2.0-3.5, likely spam
- **spam** - Score ≥ 3.5, definitely spam

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
