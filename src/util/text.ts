/**
 * Text safety helpers. All output derived from scanned (untrusted) content must
 * pass through here so a malicious artifact cannot inject terminal escapes,
 * hide characters, or leak secrets into logs.
 */

// Zero-width and bidirectional formatting characters used to hide instructions.
const FORMAT_CHARS = "\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2064\\u2066-\\u2069\\uFEFF";
const FORMAT_STRIP_RE = new RegExp(`[${FORMAT_CHARS}]`, "g");
const FORMAT_TEST_RE = new RegExp(`[${FORMAT_CHARS}]`);
// biome-ignore lint/suspicious/noControlCharactersInRegex: matching ANSI escape sequences is the intent
const ANSI_RE = /\u001b\[[0-9;]*[A-Za-z]/g;

const SECRET_PATTERNS: RegExp[] = [
  /\bsk-[A-Za-z0-9_-]{8,}\b/g,
  /\bgh[pousr]_[A-Za-z0-9]{8,}\b/g,
  /\bAKIA[0-9A-Z]{12,}\b/g,
  /\bAIza[0-9A-Za-z_-]{20,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{8,}\b/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
];

/** True when the text contains zero-width or bidi formatting characters. */
export function hasFormatChars(input: string): boolean {
  return FORMAT_TEST_RE.test(input);
}

export function stripFormatChars(input: string): string {
  return input.replace(FORMAT_STRIP_RE, "");
}

export function stripAnsi(input: string): string {
  return input.replace(ANSI_RE, "");
}

/** Replace hidden format characters with visible `\uXXXX` escapes. */
export function escapeFormatChars(input: string): string {
  return input.replace(FORMAT_STRIP_RE, (match) => {
    const code = match.codePointAt(0)?.toString(16).toUpperCase().padStart(4, "0") ?? "0000";
    return `\\u${code}`;
  });
}

/** Mask likely secrets so findings never print raw key material. */
export function redactSecrets(input: string): string {
  let output = input;
  for (const pattern of SECRET_PATTERNS) {
    output = output.replace(pattern, "[redacted]");
  }
  return output;
}

/** A single-line, control-character-free, redacted excerpt for display. */
export function toSafeSnippet(line: string, maxLength = 200): string {
  const cleaned = stripAnsi(stripFormatChars(line)).replace(/\s+/g, " ").trim();
  return redactSecrets(cleaned).slice(0, maxLength);
}

/** True when content looks binary (contains NUL bytes). */
export function looksBinary(content: string): boolean {
  return content.includes("\u0000");
}
