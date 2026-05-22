import { field, section } from "../../core/format.js";
import { bytesToSpacedHex } from "../../core/hex.js";
import {
  decodeGpRegistryData,
  decodeInitializeUpdateResponse,
} from "./shared.js";

export function decodeGlobalPlatformResponse(bytes) {
  const initializeUpdate = decodeInitializeUpdateResponse(bytes);
  if (initializeUpdate) {
    const fields = [
      field("Key diversification data", bytesToSpacedHex(bytes.slice(0, 10))),
      field("Key version number", initializeUpdate.keyVersionNumber),
      field("Secure channel protocol", initializeUpdate.scpIdentifier),
      field("SCP i-parameter", initializeUpdate.scpParameter),
      field("Sequence counter", initializeUpdate.sequenceCounter || "Not present"),
      field("Card challenge", initializeUpdate.cardChallenge),
      field("Card cryptogram", initializeUpdate.cardCryptogram),
    ];
    return {
      commandName: "INITIALIZE UPDATE response",
      category: "Secure channel",
      layer: "GlobalPlatform card management layer",
      confidence: "possible",
      shortMeaning: "Response data matches the GlobalPlatform INITIALIZE UPDATE secure-channel response structure.",
      possibleSpecArea: "GlobalPlatform Card Specification / INITIALIZE UPDATE response data",
      sections: [section("INITIALIZE UPDATE response", fields)],
      decodedFields: initializeUpdate,
      warnings: [],
    };
  }

  const registry = decodeGpRegistryData(bytes);
  if (registry) {
    const sections = [
      section("Registry response overview", [
        field("Registry entries", registry.entries.length),
        field("Payload bytes", bytesToSpacedHex(bytes)),
      ]),
    ];

    registry.entries.forEach((entry, index) => {
      sections.push(
        section(`Registry entry #${index + 1}`, [
          field("Entry TLV", entry.tlvSpacedHex || entry.tlvHex),
          field("AID", entry.aid || "Not present"),
          field("Lifecycle state", entry.lifecycle || "Not present", {
            certainty: entry.lifecycle ? "possible" : "possible",
          }),
          field("Privileges", entry.privileges?.summary || "Not present", {
            certainty: entry.privileges ? "possible" : "possible",
          }),
          field("Recognized tags", entry.tags.join(", ") || "None"),
        ]),
      );
    });

    return {
      commandName: "GlobalPlatform registry response",
      category: "GlobalPlatform management",
      layer: "GlobalPlatform card management layer",
      confidence: "possible",
      shortMeaning: "Response payload looks like GlobalPlatform registry data, such as a GET STATUS result.",
      possibleSpecArea: "GlobalPlatform Card Specification / GET STATUS response data",
      sections,
      decodedFields: {
        registryEntries: registry.entries.length,
        firstEntryAid: registry.entries[0]?.aid || "Not present",
        firstEntryPrivileges: registry.entries[0]?.privileges?.summary || "Not present",
      },
      warnings: registry.warnings,
    };
  }

  return null;
}
