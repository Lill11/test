import { ISO7816_COMMANDS } from "./iso7816/commands.js";
import { ETSI_102221_COMMANDS } from "./etsi102221/commands.js";
import { ETSI_102223_COMMANDS } from "./etsi102223/commands.js";
import { ETSI_102226_COMMANDS } from "./etsi102226/commands.js";
import { GLOBAL_PLATFORM_COMMANDS } from "./globalplatform/commands.js";
import { warning } from "../core/format.js";

export const COMMAND_REGISTRY = [
  ...GLOBAL_PLATFORM_COMMANDS,
  ...ETSI_102223_COMMANDS,
  ...ETSI_102226_COMMANDS,
  ...ETSI_102221_COMMANDS,
  ...ISO7816_COMMANDS,
];

export function matchCommand(apdu) {
  const matches = COMMAND_REGISTRY.map((command) => {
    const match = command.match(apdu);
    if (!match) {
      return null;
    }
    return { command, ...match };
  }).filter(Boolean);

  matches.sort((left, right) => right.score - left.score);
  const best = matches[0] ?? null;
  const alternatives = matches.slice(1, 4).map((entry) => ({
    name: entry.command.name,
    layer: entry.command.layer,
    score: entry.score,
    confidence: entry.confidence,
  }));

  return { best, alternatives, allMatches: matches };
}

export function analyzeCommand(apdu) {
  const matched = matchCommand(apdu);
  if (!matched.best) {
    return {
      commandName: "Unknown",
      category: "Unknown",
      layer: "Unclassified",
      possibleSpecArea: "Unknown",
      shortMeaning: "No registered command matched this CLA/INS/context combination.",
      confidence: "unclassified",
      sections: [],
      decodedFields: {},
      warnings: [
        warning("Unknown CLA/INS/context combination. Partial APDU structure was still decoded.", "warning"),
      ],
      alternatives: [],
    };
  }

  const { command, confidence } = matched.best;
  const decoded = command.decode(apdu);
  const warnings = decoded.warnings || [];
  if (matched.alternatives.length) {
    warnings.push(
      warning(
        `Alternative interpretations also matched: ${matched.alternatives.map((entry) => `${entry.name} [${entry.layer}]`).join("; ")}.`,
        "info",
      ),
    );
  }

  return {
    commandName: command.name,
    category: command.category,
    layer: command.layer,
    possibleSpecArea: command.specArea,
    shortMeaning: command.summary,
    confidence,
    sections: decoded.sections || [],
    decodedFields: decoded.decodedFields || {},
    warnings,
    alternatives: matched.alternatives,
  };
}

export function listSupportedCommands() {
  return COMMAND_REGISTRY.map((command) => ({
    name: command.name,
    category: command.category,
    layer: command.layer,
    possibleSpecArea: command.specArea,
    shortMeaning: command.summary,
  }));
}
