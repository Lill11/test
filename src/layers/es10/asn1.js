import { field, section, warning } from "../../core/format.js";
import { parseBerTlv, parseBerTlvPrefix } from "../../core/tlv.js";
import { bytesToSpacedHex } from "../../core/hex.js";

// Source: GSMA SGP.22 / SGP.23 ES10/eUICC BER-TLV tag space as used by public
// eUICC client implementations. This is a curated top-level tag map, not a full ASN.1 schema.
const ES10_TAGS = {
  BF20: "GetEuiccInfo1 / EUICCInfo1",
  BF21: "PrepareDownload",
  BF22: "GetEuiccInfo2 / EUICCInfo2",
  BF23: "InitialiseSecureChannel",
  BF24: "ConfigureISDP",
  BF25: "StoreMetadata",
  BF26: "ReplaceSessionKeyResponse",
  BF27: "ProfileInstallationReceipt",
  BF28: "ListNotification / ProfileInstallationResult",
  BF29: "SetNickname",
  BF2A: "UpdateMetadata",
  BF2B: "RetrieveNotificationsList",
  BF2D: "GetProfiles",
  BF2E: "GetEuiccChallenge",
  BF30: "RemoveNotificationFromList",
  BF31: "EnableProfile",
  BF32: "DisableProfile",
  BF33: "DeleteProfile",
  BF34: "EuiccMemoryReset",
  BF38: "AuthenticateServer",
  BF3C: "GetConfiguredAddresses",
  BF3E: "GetEID",
  BF3F: "SetDefaultSmdpAddress",
  BF43: "GetRAT",
  E3: "ProfileInfo",
};

function isEs10Tag(tagHex) {
  return Object.prototype.hasOwnProperty.call(ES10_TAGS, tagHex);
}

function summarizeTopLevelItems(items) {
  return items
    .map((item) => `${item.tagHex} ${ES10_TAGS[item.tagHex] || "Unknown ES10 tag"}`)
    .join(", ");
}

export function decodeEs10Asn1Payload(bytes) {
  const ber = parseBerTlv(bytes);
  if (!ber.items.length) {
    return null;
  }

  const topLevel = ber.items.filter((item) => isEs10Tag(item.tagHex));
  if (!topLevel.length) {
    return null;
  }

  const fields = [
    field("Payload length", bytes.length),
    field("Top-level ES10 tags", summarizeTopLevelItems(topLevel)),
    field("BER-TLV items", ber.items.length),
    field("Payload bytes", bytesToSpacedHex(bytes)),
  ];

  const nestedFields = [];
  for (const item of ber.items) {
    nestedFields.push(
      field(
        `${item.tagHex} ${ES10_TAGS[item.tagHex] || "BER item"}`,
        `${item.valueHex || "empty"} (${item.length} byte(s))`,
        {
          certainty: isEs10Tag(item.tagHex) ? "confirmed" : "possible",
          note: isEs10Tag(item.tagHex) ? "Recognized from GSMA ES10/eUICC ASN.1 tag allocations." : "",
        },
      ),
    );
  }

  return {
    commandName: "ES10 / eUICC ASN.1 payload",
    category: "GSMA eUICC / ES10 payload",
    layer: "GSMA SGP.22 / SGP.23 ES10 ASN.1 layer",
    confidence: "confirmed",
    shortMeaning: "Payload looks like GSMA eUICC ES10 ASN.1 BER-TLV data.",
    possibleSpecArea: "GSMA SGP.22 / SGP.23 ES10 ASN.1 tag space",
    sections: [
      section("ES10 / eUICC payload overview", fields),
      section("Recognized ES10 BER-TLV items", nestedFields),
    ],
    decodedFields: {
      es10TopLevelTags: topLevel.map((item) => `${item.tagHex} ${ES10_TAGS[item.tagHex]}`),
      firstEs10Tag: `${topLevel[0].tagHex} ${ES10_TAGS[topLevel[0].tagHex]}`,
    },
    warnings: [
      ...ber.warnings.map((message) => warning(message)),
      warning("ES10 ASN.1 tags were recognized; this payload was intentionally not treated as a CAT proactive command.", "info"),
    ],
  };
}

function looksPrintable(bytes) {
  if (!bytes.length) {
    return false;
  }
  return bytes.every((byte) => byte >= 0x20 && byte <= 0x7e);
}

function previewValue(bytes) {
  if (looksPrintable(bytes)) {
    return new TextDecoder("latin1").decode(Uint8Array.from(bytes));
  }
  return bytesToSpacedHex(bytes);
}

export function analyzeEs10StoreDataChunk(bytes, p1, p2) {
  const top = parseBerTlvPrefix(bytes);
  const isFinalBlock = (p1 & 0x80) !== 0;
  const sequenceNumber = p2;

  if (top.error) {
    if (sequenceNumber > 0) {
      return {
        sections: [
          section("ES10 STORE DATA chunk", [
            field("Chunk role", `Continuation block #${sequenceNumber}`, { certainty: "confirmed" }),
            field("Final block flag", isFinalBlock ? "Final chunk indicated" : "More chunks expected", {
              certainty: "confirmed",
            }),
            field("Payload bytes", bytesToSpacedHex(bytes)),
            field("Interpretation", "This block looks like a continuation fragment of a previously started ES10 / ASN.1 payload.", {
              certainty: "possible",
            }),
          ]),
        ],
        decodedFields: {
          storeDataChunkRole: `Continuation block #${sequenceNumber}`,
          storeDataChunkFinal: isFinalBlock ? "Final chunk indicated" : "More chunks expected",
          es10ChunkState: "Continuation fragment",
        },
        warnings: [],
      };
    }
    return null;
  }

  if (!isEs10Tag(top.tagHex)) {
    if (sequenceNumber > 0) {
      return {
        sections: [
          section("STORE DATA chunk analysis", [
            field("Chunk role", `Continuation block #${sequenceNumber}`, { certainty: "confirmed" }),
            field("Final block flag", isFinalBlock ? "Final chunk indicated" : "More chunks expected", {
              certainty: "confirmed",
            }),
            field("Top bytes", bytesToSpacedHex(bytes.slice(0, Math.min(24, bytes.length)))),
            field("Interpretation", "This block does not start with a top-level ES10 ASN.1 tag and likely continues a prior long payload.", {
              certainty: "possible",
            }),
          ]),
        ],
        decodedFields: {
          storeDataChunkRole: `Continuation block #${sequenceNumber}`,
          storeDataChunkFinal: isFinalBlock ? "Final chunk indicated" : "More chunks expected",
          es10ChunkState: "Continuation fragment",
        },
        warnings: [],
      };
    }
    return null;
  }

  const inner = parseBerTlv(top.availableValueBytes, { maxItems: 12 });
  const innerFields = inner.items.slice(0, 12).map((item) =>
    field(
      `${item.tagHex}`,
      `${previewValue(item.valueBytes.slice(0, Math.min(item.valueBytes.length, 48)))} (${item.length} byte(s))`,
      {
        certainty: "possible",
      },
    ),
  );

  return {
    sections: [
      section("ES10 STORE DATA chunk", [
        field("Chunk role", sequenceNumber === 0 ? "Initial chunk" : `Chunk #${sequenceNumber}`, { certainty: "confirmed" }),
        field("Final block flag", isFinalBlock ? "Final chunk indicated" : "More chunks expected", {
          certainty: "confirmed",
        }),
        field("Top-level ES10 tag", `${top.tagHex} ${ES10_TAGS[top.tagHex]}`, { certainty: "confirmed" }),
        field("Declared top-level length", `${top.length} byte(s)`),
        field(
          "Chunk completeness",
          top.isComplete ? "Top-level ES10 object is complete in this APDU" : `Chunk carries only part of the top-level object; ${top.missingValueBytes} byte(s) are still outside this APDU`,
          {
            certainty: top.isComplete ? "confirmed" : "possible",
          },
        ),
      ]),
      ...(innerFields.length ? [section("Visible inner BER-TLV items", innerFields)] : []),
    ],
    decodedFields: {
      firstEs10Tag: `${top.tagHex} ${ES10_TAGS[top.tagHex]}`,
      storeDataChunkRole: sequenceNumber === 0 ? "Initial chunk" : `Chunk #${sequenceNumber}`,
      storeDataChunkFinal: isFinalBlock ? "Final chunk indicated" : "More chunks expected",
      es10ChunkState: top.isComplete ? "Complete top-level object" : "Top-level object continues in later chunks",
    },
    warnings: top.isComplete
      ? []
      : [warning("This APDU contains only a fragment of a larger ES10 ASN.1 object; later STORE DATA chunks are needed for full decoding.", "info")],
  };
}
