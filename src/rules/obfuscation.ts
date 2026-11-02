import { escapeFormatChars, escapeTagChars, hasFormatChars, toSafeSnippet } from "../util/text.js";
import type { FileEntry, Finding, Rule } from "./types.js";

const TAG_CHAR_RE = /[\u{E0000}-\u{E007F}]/u;
// biome-ignore lint/suspicious/noMisleadingCharacterClass: variation selectors are intentionally matched as standalone code points
const VARIATION_SELECTOR_RUN_RE = /(?:\uFE00-\uFE0F|[\u{E0100}-\u{E01EF}]){8,}/u;

const zeroWidthRule: Rule = {
  id: "obf.zero-width",
  severity: "high",
  confidence: "high",
  description: "Detects hidden zero-width and bidirectional formatting characters.",
  check(entry: FileEntry): Finding[] {
    const findings: Finding[] = [];
    entry.lines.forEach((line, index) => {
      if (hasFormatChars(line)) {
        findings.push({
          ruleId: "obf.zero-width",
          severity: "high",
          confidence: "high",
          message: "Hidden zero-width/bidi characters can conceal instructions.",
          file: entry.path,
          line: index + 1,
          snippet: toSafeSnippet(escapeFormatChars(line)),
          remediation: "Remove hidden formatting characters and review the original text.",
        });
      }
    });
    return findings;
  },
};

const BASE64_RE = /[A-Za-z0-9+/]{40,}={0,2}/g;
const HEX_RE = /\b[0-9a-fA-F]{64,}\b/g;
const SUSPICIOUS_DECODED_RE =
  /\b(ignore\s+(?:all|any|the)?\s*(?:previous|prior)|do not tell|exfiltrat|\.env|curl\s|wget\s|https?:\/\/|secret|password|token|api[_-]?key|eval\(|exec\(|child_process)\b/i;

function decodeBase64(value: string): string | null {
  try {
    const text = Buffer.from(value, "base64").toString("utf8");
    return text.length > 0 ? text : null;
  } catch {
    return null;
  }
}

function isPrintable(text: string): boolean {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: detecting control characters is the intent
  return !/[\u0000-\u0008\u000E-\u001F]/.test(text);
}

const encodedBlobRule: Rule = {
  id: "obf.encoded-blob",
  severity: "high",
  confidence: "medium",
  description: "Encoded blob (base64/hex) that decodes to suspicious instructions.",
  check(entry: FileEntry): Finding[] {
    const findings: Finding[] = [];
    entry.lines.forEach((line, index) => {
      const candidates = [...line.matchAll(BASE64_RE)].map((match) => match[0]);
      for (const candidate of candidates) {
        const decoded = decodeBase64(candidate);
        if (decoded && isPrintable(decoded) && SUSPICIOUS_DECODED_RE.test(decoded)) {
          findings.push({
            ruleId: "obf.encoded-blob",
            severity: "high",
            confidence: "medium",
            message: "A base64 blob decodes to suspicious instructions.",
            file: entry.path,
            line: index + 1,
            snippet: toSafeSnippet(decoded),
            remediation: "Decode and review the blob; remove it if it is not legitimate data.",
          });
          return;
        }
      }
      // Hex-encoded payloads are less common; only note when they decode to keywords.
      for (const match of line.matchAll(HEX_RE)) {
        const decoded = Buffer.from(match[0], "hex").toString("utf8");
        if (isPrintable(decoded) && SUSPICIOUS_DECODED_RE.test(decoded)) {
          findings.push({
            ruleId: "obf.encoded-blob",
            severity: "high",
            confidence: "low",
            message: "A hex blob decodes to suspicious instructions.",
            file: entry.path,
            line: index + 1,
            snippet: toSafeSnippet(decoded),
            remediation: "Decode and review the blob; remove it if it is not legitimate data.",
          });
          return;
        }
      }
    });
    return findings;
  },
};

const CONFUSABLE_RE = /[\u0400-\u04FF\u0370-\u03FF]/;
const ASCII_LETTER_RE = /[A-Za-z]/;

const homoglyphRule: Rule = {
  id: "obf.homoglyph",
  severity: "medium",
  confidence: "low",
  description: "Mixed-script characters that may spoof words or identifiers.",
  check(entry: FileEntry): Finding[] {
    const findings: Finding[] = [];
    entry.lines.forEach((line, index) => {
      for (const token of line.split(/\s+/)) {
        if (ASCII_LETTER_RE.test(token) && CONFUSABLE_RE.test(token)) {
          findings.push({
            ruleId: "obf.homoglyph",
            severity: "medium",
            confidence: "low",
            message: "Token mixes Latin letters with confusable non-Latin characters.",
            file: entry.path,
            line: index + 1,
            snippet: toSafeSnippet(token),
            remediation: "Check the identifier for deliberate look-alike characters.",
          });
          break;
        }
      }
    });
    return findings;
  },
};

export const unicodeTagRule: Rule = {
  id: "obf.unicode-tag",
  severity: "high",
  confidence: "high",
  description: "Unicode tag characters or long variation-selector runs hide text.",
  check(entry: FileEntry): Finding[] {
    const findings: Finding[] = [];
    entry.lines.forEach((line, index) => {
      const tag = TAG_CHAR_RE.test(line);
      const selectors = VARIATION_SELECTOR_RUN_RE.test(line);
      if (!tag && !selectors) {
        return;
      }
      findings.push({
        ruleId: "obf.unicode-tag",
        severity: "high",
        confidence: "high",
        message: tag
          ? "Unicode tag characters can hide an invisible ASCII payload."
          : "A long variation-selector run can hide data.",
        file: entry.path,
        line: index + 1,
        snippet: toSafeSnippet(
          escapeTagChars(line).replace(VARIATION_SELECTOR_RUN_RE, "[variation-selectors]"),
        ),
        remediation: "Strip invisible formatting characters and review the original text.",
      });
    });
    return findings;
  },
};

export const obfuscationRules: Rule[] = [
  zeroWidthRule,
  unicodeTagRule,
  encodedBlobRule,
  homoglyphRule,
];
