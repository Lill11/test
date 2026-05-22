export function toHex(value, width = 2) {
  return value.toString(16).toUpperCase().padStart(width, "0");
}

export function bytesToHex(bytes) {
  return bytes.map((byte) => toHex(byte)).join("");
}

export function bytesToSpacedHex(bytes) {
  return bytes.map((byte) => toHex(byte)).join(" ");
}

export function formatByteRange(start, endInclusive) {
  return start === endInclusive ? `B${start}` : `B${start}-B${endInclusive}`;
}

export function stripComments(rawLine) {
  return rawLine.replace(/\/\/.*$/g, "").replace(/#.*/g, "").trim();
}

function normalizeSegment(segment) {
  return segment.replace(/^0x/gi, "").replace(/[^0-9a-f]/gi, "");
}

export function extractHexBytes(rawLine) {
  const line = stripComments(rawLine);
  if (!line) {
    return { bytes: [], normalizedHex: "", warnings: [] };
  }

  const compact = line.replace(/[\s,;:_-]+/g, "");
  if (/^(?:0x)?[0-9a-f]+$/i.test(compact)) {
    const normalized = normalizeSegment(compact);
    if (normalized.length % 2 !== 0) {
      return {
        bytes: [],
        normalizedHex: normalized,
        warnings: ["Hex input has an odd number of nybbles."],
      };
    }
    const bytes = normalized.match(/.{2}/g)?.map((chunk) => Number.parseInt(chunk, 16)) ?? [];
    return { bytes, normalizedHex: normalized, warnings: [] };
  }

  const runPattern = /((?:(?:0x)?[0-9A-Fa-f]{2})(?:[\s,;:_-]+(?:0x)?[0-9A-Fa-f]{2}){3,})/g;
  const runs = [...line.matchAll(runPattern)].map((match) => match[1]);
  if (runs.length === 0) {
    return {
      bytes: [],
      normalizedHex: "",
      warnings: ["No APDU-like byte sequence was found in this line."],
    };
  }

  const bestRun = runs.sort((left, right) => right.length - left.length)[0];
  const normalized = bestRun
    .split(/[\s,;:_-]+/)
    .map(normalizeSegment)
    .filter(Boolean)
    .join("");
  const bytes = normalized.match(/.{2}/g)?.map((chunk) => Number.parseInt(chunk, 16)) ?? [];
  const warnings = [];

  if (runs.length > 1) {
    warnings.push("Multiple byte runs were present; the analyzer used the longest APDU-looking run.");
  }

  return { bytes, normalizedHex: normalized, warnings };
}
