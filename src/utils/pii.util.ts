export type PiiType = 'EMAIL' | 'PHONE' | 'IL_ID';

export interface PiiMatch {
  type: PiiType;
  value: string;
  start: number;
  end: number;
}

// Pattern sources — compiled fresh each call to avoid shared lastIndex state
const EMAIL_SRC =
  /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/.source;

// Israeli mobile (05X) and landline (0X), with optional +972 prefix
const IL_PHONE_SRC =
  /(?:\+972[-\s]?|0)(?:5[0-9]|[2-9])[-\s]?\d{3}[-\s]?\d{4}/.source;

// International E.164 (explicitly excludes +972 to avoid double-match)
const INTL_PHONE_SRC =
  /\+(?!972)\d{1,3}[-\s]?\(?\d{1,4}\)?[-\s]?\d{1,4}[-\s]?\d{1,9}/.source;

// 9-digit candidate (validated with checksum below)
const IL_ID_SRC = /\b\d{9}\b/.source;

/**
 * Israeli National ID checksum (Luhn-variant as published by the Population Authority).
 * Weights alternate 1/2; products > 9 have 9 subtracted; valid if total % 10 === 0.
 */
export function isValidIsraeliId(id: string): boolean {
  if (!/^\d{9}$/.test(id)) return false;
  let total = 0;
  for (let i = 0; i < 9; i++) {
    const digit = id.charCodeAt(i) - 48; // faster than parseInt
    let val = digit * (i % 2 === 0 ? 1 : 2);
    if (val > 9) val -= 9;
    total += val;
  }
  return total % 10 === 0;
}

/** Collect all non-overlapping PII occurrences, sorted by position. */
export function findPii(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];

  const push = (type: PiiType, re: RegExp): void => {
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      matches.push({ type, value: m[0], start: m.index, end: m.index + m[0].length });
    }
  };

  push('EMAIL', new RegExp(EMAIL_SRC, 'g'));
  push('PHONE', new RegExp(IL_PHONE_SRC, 'g'));

  // Intl phones: skip positions already claimed by an IL_PHONE match
  const intlRe = new RegExp(INTL_PHONE_SRC, 'g');
  let m: RegExpExecArray | null;
  while ((m = intlRe.exec(text)) !== null) {
    const pos = m.index;
    if (!matches.some((x) => x.type === 'PHONE' && x.start === pos)) {
      matches.push({ type: 'PHONE', value: m[0], start: pos, end: pos + m[0].length });
    }
  }

  // IL IDs: only keep 9-digit sequences that pass the checksum
  const idRe = new RegExp(IL_ID_SRC, 'g');
  while ((m = idRe.exec(text)) !== null) {
    if (isValidIsraeliId(m[0])) {
      matches.push({ type: 'IL_ID', value: m[0], start: m.index, end: m.index + m[0].length });
    }
  }

  // Sort then remove overlaps (keep the first/longest match at each position)
  matches.sort((a, b) => a.start - b.start || b.end - a.end);
  return removeOverlaps(matches);
}

function removeOverlaps(sorted: PiiMatch[]): PiiMatch[] {
  const result: PiiMatch[] = [];
  let cursor = -1;
  for (const m of sorted) {
    if (m.start >= cursor) {
      result.push(m);
      cursor = m.end;
    }
  }
  return result;
}

export interface PiiCounters {
  EMAIL: number;
  PHONE: number;
  IL_ID: number;
}

export interface RedactionResult {
  redacted: string;
  /** Ordered list of replacements applied */
  mappings: Array<{ token: string; original: string }>;
  totalReplaced: number;
}

/**
 * Replace all PII in `text` with reversible tokens.
 * `counters` is mutated so callers can maintain a global counter across multiple texts.
 */
export function redactPii(text: string, counters: PiiCounters): RedactionResult {
  const piiMatches = findPii(text);
  if (piiMatches.length === 0) {
    return { redacted: text, mappings: [], totalReplaced: 0 };
  }

  const mappings: Array<{ token: string; original: string }> = [];
  let result = '';
  let cursor = 0;

  for (const match of piiMatches) {
    result += text.slice(cursor, match.start);
    counters[match.type] += 1;
    const token = `<PII_${match.type}_${counters[match.type]}>`;
    result += token;
    mappings.push({ token, original: match.value });
    cursor = match.end;
  }

  result += text.slice(cursor);
  return { redacted: result, mappings, totalReplaced: piiMatches.length };
}
