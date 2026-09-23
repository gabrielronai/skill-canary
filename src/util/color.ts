import type { Severity } from "../rules/types.js";

const CODES: Record<Severity, string> = {
  critical: "\u001b[41;97m",
  high: "\u001b[31m",
  medium: "\u001b[33m",
  low: "\u001b[36m",
  info: "\u001b[90m",
};

const RESET = "\u001b[0m";
const BOLD = "\u001b[1m";
const DIM = "\u001b[2m";

export function colorize(text: string, severity: Severity, enabled: boolean): string {
  return enabled ? `${CODES[severity]}${text}${RESET}` : text;
}

export function bold(text: string, enabled: boolean): string {
  return enabled ? `${BOLD}${text}${RESET}` : text;
}

export function dim(text: string, enabled: boolean): string {
  return enabled ? `${DIM}${text}${RESET}` : text;
}
