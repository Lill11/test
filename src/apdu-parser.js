import { extractHexBytes } from "./core/hex.js";
import { warning } from "./core/format.js";
import { parseCommandApdu } from "./iso7816/apdu-structure.js";
import { analyzeCommand } from "./layers/index.js";
import { analyzePayloadLine, analyzeResponseLine } from "./response-parser.js";

function buildErrorResult(lineNumber, rawApdu, message, extraWarnings = []) {
  return {
    lineNumber,
    rawApdu,
    normalizedHex: "",
    commandName: "Unknown",
    category: "Unknown",
    layer: "Unclassified",
    caseType: "unparsed",
    extendedLength: false,
    decodedFields: {},
    sections: [],
    shortMeaning: "Could not parse this APDU line.",
    possibleSpecArea: "Unknown",
    warnings: [message, ...extraWarnings],
    warningDetails: [warning(message, "error"), ...extraWarnings.map((current) => warning(current))],
    alternatives: [],
    confidence: "error",
  };
}

export function parseApduLine(rawLine, lineNumber) {
  const trimmed = rawLine.trim();
  if (!trimmed) {
    return null;
  }

  const extracted = extractHexBytes(trimmed);
  if (extracted.warnings.length && extracted.bytes.length === 0) {
    return buildErrorResult(lineNumber, trimmed, extracted.warnings[0], extracted.warnings.slice(1));
  }

  const { bytes, warnings: extractionWarnings } = extracted;
  if (bytes.length < 2) {
    return buildErrorResult(lineNumber, trimmed, "At least one byte pair is required to analyze this line.", extractionWarnings);
  }

  const responseAnalysis = analyzeResponseLine(bytes);
  if (responseAnalysis?.responseData?.bytes?.[0] === 0xd0 || (responseAnalysis && bytes.length <= 2)) {
    return {
      lineNumber,
      ...responseAnalysis,
      warnings: [...extractionWarnings, ...responseAnalysis.warnings.map((entry) => entry.message)],
      warningDetails: [...extractionWarnings.map((message) => warning(message)), ...responseAnalysis.warnings],
    };
  }

  let parsedApdu = null;
  let commandAnalysis = null;
  if (bytes.length >= 4) {
    parsedApdu = parseCommandApdu(bytes);
    if (parsedApdu.ok) {
      commandAnalysis = analyzeCommand(parsedApdu);
    }
  }

  if (responseAnalysis && (!parsedApdu || !parsedApdu.ok || commandAnalysis?.commandName === "Unknown")) {
    return {
      lineNumber,
      ...responseAnalysis,
      warnings: [...extractionWarnings, ...responseAnalysis.warnings.map((entry) => entry.message)],
      warningDetails: [...extractionWarnings.map((message) => warning(message)), ...responseAnalysis.warnings],
    };
  }

  const payloadAnalysis = analyzePayloadLine(bytes);
  if ((!parsedApdu || !parsedApdu.ok || commandAnalysis?.commandName === "Unknown") && payloadAnalysis.commandName !== "Unknown payload") {
    return {
      lineNumber,
      rawApdu: payloadAnalysis.rawApdu || extracted.bytes.map((byte) => byte.toString(16).toUpperCase().padStart(2, "0")).join(" "),
      normalizedHex: extracted.normalizedHex,
      ...payloadAnalysis,
      warnings: [...extractionWarnings, ...payloadAnalysis.warnings.map((entry) => entry.message)],
      warningDetails: [...extractionWarnings.map((message) => warning(message)), ...payloadAnalysis.warnings],
    };
  }

  if ((!parsedApdu || !parsedApdu.ok) && payloadAnalysis.commandName === "Unknown payload") {
    return buildErrorResult(lineNumber, trimmed, parsedApdu?.error || "Line is not a recognized APDU or structured payload.", extractionWarnings);
  }

  if (!parsedApdu || !parsedApdu.ok) {
    return {
      lineNumber,
      rawApdu: extracted.bytes.map((byte) => byte.toString(16).toUpperCase().padStart(2, "0")).join(" "),
      normalizedHex: extracted.normalizedHex,
      ...payloadAnalysis,
      warnings: [...extractionWarnings, ...payloadAnalysis.warnings.map((entry) => entry.message)],
      warningDetails: [...extractionWarnings.map((message) => warning(message)), ...payloadAnalysis.warnings],
    };
  }

  const analysis = commandAnalysis;
  const structuralWarnings = [...extractionWarnings, ...parsedApdu.warnings];
  const warningDetails = [...structuralWarnings.map((message) => warning(message)), ...(analysis.warnings || [])];

  if (parsedApdu.cla.commandChaining) {
    warningDetails.push(
      warning("Command chaining bit is set; adjacent APDUs may be required to understand the full transaction.", "info"),
    );
  }
  if (parsedApdu.extendedLength) {
    warningDetails.push(
      warning("Extended-length APDU detected; ensure the capture preserved the complete command body.", "info"),
    );
  }

  return {
    lineNumber,
    kind: "command-apdu",
    rawApdu: parsedApdu.rawApdu,
    normalizedHex: parsedApdu.normalizedHex,
    cla: parsedApdu.cla,
    ins: parsedApdu.ins,
    p1: parsedApdu.p1,
    p2: parsedApdu.p2,
    lc: parsedApdu.lc,
    data: parsedApdu.data,
    le: parsedApdu.le,
    caseType: parsedApdu.caseType,
    extendedLength: parsedApdu.extendedLength,
    commandName: analysis.commandName,
    category: analysis.category,
    layer: analysis.layer,
    confidence: analysis.confidence,
    decodedFields: {
      claType: parsedApdu.cla.classType,
      logicalChannel: parsedApdu.cla.logicalChannel,
      secureMessaging: parsedApdu.cla.secureMessaging ? "Present / indicated" : "Not indicated",
      commandChaining: parsedApdu.cla.commandChaining ? "Set" : "Not set",
      p1: `0x${parsedApdu.p1Hex}`,
      p2: `0x${parsedApdu.p2Hex}`,
      ...analysis.decodedFields,
    },
    sections: analysis.sections,
    shortMeaning: analysis.shortMeaning,
    possibleSpecArea: analysis.possibleSpecArea,
    warnings: warningDetails.map((entry) => entry.message),
    warningDetails,
    alternatives: analysis.alternatives,
  };
}

export function parseApduText(sourceText) {
  return sourceText
    .split(/\r?\n/)
    .map((line, index) => parseApduLine(line, index + 1))
    .filter(Boolean);
}
