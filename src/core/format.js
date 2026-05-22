import { bytesToSpacedHex } from "./hex.js";

export function field(label, value, options = {}) {
  return {
    label,
    value,
    certainty: options.certainty || "confirmed",
    byteRange: options.byteRange || null,
    note: options.note || "",
  };
}

export function section(title, fields = []) {
  return { title, fields };
}

export function warning(message, severity = "warning") {
  return { message, severity };
}

export function bytesSummary(bytes) {
  return bytes.length ? bytesToSpacedHex(bytes) : "None";
}
