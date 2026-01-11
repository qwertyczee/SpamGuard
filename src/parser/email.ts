// ============================================================================
// Email Parser
// Parses raw MIME emails and structured email objects
// ============================================================================

import type {
    EmailInput,
    ParsedEmail,
    EmailAddress,
    Attachment,
    ReceivedHeader,
} from "../types";

/**
 * Parse an email from various input formats
 */
export function parseEmail(input: EmailInput): ParsedEmail {
    if (input.raw) {
        return parseRawEmail(input.raw);
    }

    return parseStructuredEmail(input);
}

/**
 * Parse a structured email input object
 */
function parseStructuredEmail(input: EmailInput): ParsedEmail {
    const headers = new Map<string, string[]>();

    // Add provided headers
    if (input.headers) {
        for (const [key, value] of Object.entries(input.headers)) {
            const normalizedKey = key.toLowerCase();
            if (Array.isArray(value)) {
                headers.set(normalizedKey, value);
            } else {
                headers.set(normalizedKey, [value]);
            }
        }
    }

    // Add individual header fields
    if (input.from) addHeader(headers, "from", input.from);
    if (input.to) {
        const toList = Array.isArray(input.to) ? input.to : [input.to];
        for (const to of toList) {
            addHeader(headers, "to", to);
        }
    }
    if (input.subject) addHeader(headers, "subject", input.subject);
    if (input.messageId) addHeader(headers, "message-id", input.messageId);
    if (input.date) addHeader(headers, "date", input.date);
    if (input.replyTo) addHeader(headers, "reply-to", input.replyTo);
    if (input.returnPath) addHeader(headers, "return-path", input.returnPath);
    if (input.receivedSpf)
        addHeader(headers, "received-spf", input.receivedSpf);
    if (input.dkimSignature)
        addHeader(headers, "dkim-signature", input.dkimSignature);
    if (input.authenticationResults) {
        addHeader(
            headers,
            "authentication-results",
            input.authenticationResults,
        );
    }

    return {
        headers,
        subject: input.subject || "",
        from: parseEmailAddress(input.from || ""),
        to: (Array.isArray(input.to) ? input.to : [input.to || ""])
            .map(parseEmailAddress)
            .filter((e): e is EmailAddress => e !== null),
        replyTo: parseEmailAddress(input.replyTo || ""),
        returnPath: input.returnPath || null,
        messageId: input.messageId || null,
        date: input.date ? new Date(input.date) : null,
        textBody: input.textBody || "",
        htmlBody: input.htmlBody || "",
        attachments: [],
        receivedChain: parseReceivedHeaders(headers.get("received") || []),
    };
}

/**
 * Parse a raw MIME email
 */
function parseRawEmail(raw: string): ParsedEmail {
    const lines = raw.split(/\r?\n/);
    const headers = new Map<string, string[]>();
    let currentHeader = "";
    let currentValue = "";
    let bodyStartIndex = 0;

    // Parse headers
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Empty line marks end of headers
        if (line === "") {
            if (currentHeader) {
                addHeader(headers, currentHeader, currentValue.trim());
            }
            bodyStartIndex = i + 1;
            break;
        }

        // Continuation of previous header (starts with whitespace)
        if (line.match(/^\s/) && currentHeader) {
            currentValue += " " + line.trim();
            continue;
        }

        // New header
        if (currentHeader) {
            addHeader(headers, currentHeader, currentValue.trim());
        }

        const colonIndex = line.indexOf(":");
        if (colonIndex > 0) {
            currentHeader = line.substring(0, colonIndex).toLowerCase();
            currentValue = line.substring(colonIndex + 1).trim();
        }
    }

    // Get body
    const bodyLines = lines.slice(bodyStartIndex);
    const body = bodyLines.join("\n");

    // Parse MIME if present
    const contentType = getHeader(headers, "content-type") || "text/plain";
    const { textBody, htmlBody, attachments } = parseMimeBody(
        body,
        contentType,
    );

    return {
        headers,
        subject: decodeHeader(getHeader(headers, "subject") || ""),
        from: parseEmailAddress(getHeader(headers, "from") || ""),
        to: (headers.get("to") || [])
            .map(decodeHeader)
            .flatMap((h) => h.split(","))
            .map(parseEmailAddress)
            .filter((e): e is EmailAddress => e !== null),
        replyTo: parseEmailAddress(getHeader(headers, "reply-to") || ""),
        returnPath: getHeader(headers, "return-path"),
        messageId: getHeader(headers, "message-id"),
        date: parseDate(getHeader(headers, "date")),
        textBody,
        htmlBody,
        attachments,
        receivedChain: parseReceivedHeaders(headers.get("received") || []),
    };
}

/**
 * Parse email address from header value
 */
export function parseEmailAddress(value: string): EmailAddress | null {
    if (!value || value.trim() === "") return null;

    value = decodeHeader(value).trim();

    // Format: "Name" <email@example.com> or Name <email@example.com>
    const bracketMatch = value.match(/^(?:"?([^"<]*)"?\s*)?<([^>]+)>/);
    if (bracketMatch) {
        const address = bracketMatch[2].trim().toLowerCase();
        const atIndex = address.indexOf("@");

        if (atIndex === -1) return null;

        return {
            name: bracketMatch[1]?.trim() || null,
            address,
            localPart: address.substring(0, atIndex),
            domain: address.substring(atIndex + 1),
        };
    }

    // Just email@example.com
    const simpleMatch = value.match(
        /^([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$/,
    );
    if (simpleMatch) {
        const address = simpleMatch[1].toLowerCase();
        const atIndex = address.indexOf("@");

        return {
            name: null,
            address,
            localPart: address.substring(0, atIndex),
            domain: address.substring(atIndex + 1),
        };
    }

    // Try to extract email from anywhere in the string
    const emailMatch = value.match(
        /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/,
    );
    if (emailMatch) {
        const address = emailMatch[1].toLowerCase();
        const atIndex = address.indexOf("@");
        const name = value
            .replace(emailMatch[0], "")
            .replace(/[<>]/g, "")
            .trim();

        return {
            name: name || null,
            address,
            localPart: address.substring(0, atIndex),
            domain: address.substring(atIndex + 1),
        };
    }

    return null;
}

/**
 * Parse Received headers
 */
function parseReceivedHeaders(receivedHeaders: string[]): ReceivedHeader[] {
    return receivedHeaders.map((header) => {
        const fromMatch = header.match(/from\s+([^\s]+)/i);
        const byMatch = header.match(/by\s+([^\s]+)/i);
        const withMatch = header.match(/with\s+([^\s;]+)/i);
        const dateMatch = header.match(/;\s*(.+)$/);

        return {
            from: fromMatch?.[1] || null,
            by: byMatch?.[1] || null,
            with: withMatch?.[1] || null,
            timestamp: dateMatch ? parseDate(dateMatch[1]) : null,
            raw: header,
        };
    });
}

/**
 * Parse MIME body
 */
function parseMimeBody(
    body: string,
    contentType: string,
): { textBody: string; htmlBody: string; attachments: Attachment[] } {
    const attachments: Attachment[] = [];

    // Check if multipart
    const boundaryMatch = contentType.match(/boundary=["']?([^"'\s;]+)["']?/i);

    if (!boundaryMatch) {
        // Simple body
        if (contentType.includes("text/html")) {
            return { textBody: "", htmlBody: body, attachments };
        }
        return { textBody: body, htmlBody: "", attachments };
    }

    const boundary = boundaryMatch[1];
    const parts = body.split(new RegExp(`--${escapeRegex(boundary)}`));

    let textBody = "";
    let htmlBody = "";

    for (const part of parts) {
        if (part.trim() === "" || part.trim() === "--") continue;

        const partLines = part.split(/\r?\n/);
        const partHeaders = new Map<string, string[]>();
        let partBodyStart = 0;
        let currentHeader = "";
        let currentValue = "";

        // Parse part headers
        for (let i = 0; i < partLines.length; i++) {
            const line = partLines[i];

            if (line === "") {
                if (currentHeader) {
                    addHeader(partHeaders, currentHeader, currentValue.trim());
                }
                partBodyStart = i + 1;
                break;
            }

            if (line.match(/^\s/) && currentHeader) {
                currentValue += " " + line.trim();
                continue;
            }

            if (currentHeader) {
                addHeader(partHeaders, currentHeader, currentValue.trim());
            }

            const colonIndex = line.indexOf(":");
            if (colonIndex > 0) {
                currentHeader = line.substring(0, colonIndex).toLowerCase();
                currentValue = line.substring(colonIndex + 1).trim();
            }
        }

        const partBody = partLines.slice(partBodyStart).join("\n");
        const partContentType =
            getHeader(partHeaders, "content-type") || "text/plain";
        const contentDisposition =
            getHeader(partHeaders, "content-disposition") || "";

        // Check if it's an attachment
        if (contentDisposition.includes("attachment")) {
            const filenameMatch = contentDisposition.match(
                /filename=["']?([^"'\s;]+)["']?/i,
            );
            attachments.push({
                filename: filenameMatch?.[1] || "unnamed",
                contentType: partContentType.split(";")[0].trim(),
                size: partBody.length,
                isInline: false,
            });
            continue;
        }

        if (partContentType.includes("text/plain") && !textBody) {
            textBody = decodeBody(partBody, partHeaders);
        } else if (partContentType.includes("text/html") && !htmlBody) {
            htmlBody = decodeBody(partBody, partHeaders);
        } else if (partContentType.includes("multipart/")) {
            // Recursive multipart
            const nested = parseMimeBody(partBody, partContentType);
            if (!textBody) textBody = nested.textBody;
            if (!htmlBody) htmlBody = nested.htmlBody;
            attachments.push(...nested.attachments);
        }
    }

    return { textBody, htmlBody, attachments };
}

/**
 * Decode body based on transfer encoding
 */
function decodeBody(body: string, headers: Map<string, string[]>): string {
    const encoding = getHeader(
        headers,
        "content-transfer-encoding",
    )?.toLowerCase();

    if (encoding === "base64") {
        try {
            return atob(body.replace(/\s/g, ""));
        } catch {
            return body;
        }
    }

    if (encoding === "quoted-printable") {
        return decodeQuotedPrintable(body);
    }

    return body;
}

/**
 * Decode quoted-printable encoding
 */
function decodeQuotedPrintable(text: string): string {
    return text
        .replace(/=\r?\n/g, "")
        .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) =>
            String.fromCharCode(parseInt(hex, 16)),
        );
}

/**
 * Decode MIME encoded header (=?charset?encoding?text?=)
 */
function decodeHeader(value: string): string {
    return value.replace(
        /=\?([^?]+)\?([BQ])\?([^?]+)\?=/gi,
        (_, charset, encoding, text) => {
            if (encoding.toUpperCase() === "B") {
                try {
                    return atob(text);
                } catch {
                    return text;
                }
            }
            if (encoding.toUpperCase() === "Q") {
                return decodeQuotedPrintable(text.replace(/_/g, " "));
            }
            return text;
        },
    );
}

/**
 * Parse date string to Date object
 */
function parseDate(dateStr: string | null | undefined): Date | null {
    if (!dateStr) return null;

    try {
        const date = new Date(dateStr);
        return isNaN(date.getTime()) ? null : date;
    } catch {
        return null;
    }
}

/**
 * Helper to add header to map
 */
function addHeader(
    headers: Map<string, string[]>,
    key: string,
    value: string,
): void {
    const normalizedKey = key.toLowerCase();
    const existing = headers.get(normalizedKey) || [];
    existing.push(value);
    headers.set(normalizedKey, existing);
}

/**
 * Helper to get first header value
 */
function getHeader(headers: Map<string, string[]>, key: string): string | null {
    const values = headers.get(key.toLowerCase());
    return values?.[0] || null;
}

/**
 * Escape string for use in regex
 */
function escapeRegex(string: string): string {
    return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
