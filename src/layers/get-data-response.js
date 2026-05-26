import { bytesToHex, bytesToSpacedHex } from "../core/hex.js";
import { field, section, warning } from "../core/format.js";
import { parseBerTlv } from "../core/tlv.js";

const GET_DATA_TAG_NAMES = {
  "0x0066": "Card data / Card Recognition Data",
  "0x00C1": "Sequence counter",
  "0x00E0": "Key information template",
  "0x2F00": "List of applications",
  "0xFF21": "Extended Card Resources Information",
  "0x9F7F": "CPLC data",
};

const CPLC_FIELD_NAMES = [
  "IC fabricator",
  "IC type",
  "Operating system provider identifier",
  "Operating system release date",
  "Operating system release level",
  "IC fabrication date",
  "IC serial number",
  "IC batch identifier",
  "IC module fabricator",
  "IC module packaging date",
  "ICC manufacturer",
  "IC embedding date",
  "IC pre-personalizer",
  "IC pre-personalization date",
  "IC pre-personalization equipment",
  "IC personalizer",
  "IC personalization date",
  "IC personalization equipment",
];

function decodeOid(valueBytes) {
  if (!valueBytes.length) {
    return "Empty OID";
  }
  const first = valueBytes[0];
  const parts = [Math.floor(first / 40), first % 40];
  let current = 0;
  for (let index = 1; index < valueBytes.length; index += 1) {
    current = (current << 7) | (valueBytes[index] & 0x7f);
    if ((valueBytes[index] & 0x80) === 0) {
      parts.push(current);
      current = 0;
    }
  }
  if (current !== 0) {
    parts.push(current);
  }
  return parts.join(".");
}

function unwrapIfTagged(bytes, tagHex) {
  const ber = parseBerTlv(bytes);
  if (ber.items.length === 1 && ber.items[0].tagHex === tagHex) {
    return {
      rawTlv: ber.items[0].tlvSpacedHex || ber.items[0].tlvHex,
      valueBytes: ber.items[0].valueBytes,
      warnings: ber.warnings.map((message) => warning(message)),
    };
  }
  return {
    rawTlv: null,
    valueBytes: bytes,
    warnings: ber.warnings.map((message) => warning(message)),
  };
}

function decodeCplc(bytes) {
  const unwrapped = unwrapIfTagged(bytes, "9F7F");
  const valueBytes = unwrapped.valueBytes;
  const fields = [];
  const decodedFields = {};
  for (let index = 0; index < Math.floor(valueBytes.length / 2); index += 1) {
    const start = index * 2;
    const value = bytesToHex(valueBytes.slice(start, start + 2));
    const label = CPLC_FIELD_NAMES[index] || `CPLC field #${index + 1}`;
    fields.push(field(label, value));
    if (index === 0) {
      decodedFields.icFabricator = value;
    } else if (index === 1) {
      decodedFields.icType = value;
    }
  }
  if (valueBytes.length % 2 !== 0) {
    fields.push(field("Trailing byte", bytesToHex(valueBytes.slice(-1)), { certainty: "possible" }));
  }
  return {
    sections: [
      section("GET DATA response", [
        field("Tag", "0x9F7F"),
        field("Object", "CPLC data"),
        field("Response bytes", bytesToSpacedHex(bytes)),
        ...(unwrapped.rawTlv ? [field("Wrapped TLV", unwrapped.rawTlv)] : []),
      ]),
      section("CPLC fields", fields),
    ],
    decodedFields: {
      getDataTagReference: "0x9F7F",
      getDataObjectName: "CPLC data",
      ...decodedFields,
    },
    warnings: unwrapped.warnings,
  };
}

function decodeCardRecognition(bytes) {
  const ber = parseBerTlv(bytes);
  const top = ber.items[0]?.tagHex === "66" ? ber.items[0] : null;
  const innerBytes = top ? top.valueBytes : bytes;
  const inner = parseBerTlv(innerBytes);
  let oid = null;
  const fields = [
    field("Tag", "0x0066"),
    field("Object", "Card data / Card Recognition Data"),
    field("Response bytes", bytesToSpacedHex(bytes)),
  ];
  if (top) {
    fields.push(field("Card data TLV", top.tlvSpacedHex || top.tlvHex));
  }
  for (const item of inner.items) {
    fields.push(field(`Tag ${item.tagHex}`, item.tlvSpacedHex || item.tlvHex));
    if (item.tagHex === "73") {
      const nested = parseBerTlv(item.valueBytes);
      for (const nestedItem of nested.items) {
        fields.push(field(`Tag ${nestedItem.tagHex}`, nestedItem.tlvSpacedHex || nestedItem.tlvHex));
        if (nestedItem.tagHex === "06") {
          oid = decodeOid(nestedItem.valueBytes);
          fields.push(field("Card recognition OID", oid));
        }
      }
    }
  }
  return {
    sections: [section("GET DATA response", fields)],
    decodedFields: {
      getDataTagReference: "0x0066",
      getDataObjectName: "Card data / Card Recognition Data",
      cardRecognitionOid: oid || "Not present",
    },
    warnings: [...ber.warnings.map((message) => warning(message)), ...inner.warnings.map((message) => warning(message))],
  };
}

function decodeKeyInformationTemplate(bytes) {
  const unwrapped = unwrapIfTagged(bytes, "E0");
  const inner = parseBerTlv(unwrapped.valueBytes);
  const fields = [
    field("Tag", "0x00E0"),
    field("Object", "Key information template"),
    field("Response bytes", bytesToSpacedHex(bytes)),
    ...(unwrapped.rawTlv ? [field("Wrapped TLV", unwrapped.rawTlv)] : []),
    field("Key information entries", inner.items.length),
  ];
  inner.items.forEach((item, index) => {
    fields.push(field(`Entry #${index + 1}`, item.tlvSpacedHex || item.tlvHex, { certainty: "possible" }));
  });
  return {
    sections: [section("GET DATA response", fields)],
    decodedFields: {
      getDataTagReference: "0x00E0",
      getDataObjectName: "Key information template",
      keyInformationEntries: inner.items.length,
    },
    warnings: [...unwrapped.warnings, ...inner.warnings.map((message) => warning(message))],
  };
}

function decodeSequenceCounter(bytes) {
  const unwrapped = unwrapIfTagged(bytes, "C1");
  const counterValue = bytesToHex(unwrapped.valueBytes);
  return {
    sections: [
      section("GET DATA response", [
        field("Tag", "0x00C1"),
        field("Object", "Sequence counter"),
        field("Response bytes", bytesToSpacedHex(bytes)),
        ...(unwrapped.rawTlv ? [field("Wrapped TLV", unwrapped.rawTlv)] : []),
        field("Sequence counter", counterValue || "Empty"),
      ]),
    ],
    decodedFields: {
      getDataTagReference: "0x00C1",
      getDataObjectName: "Sequence counter",
      sequenceCounter: counterValue || "Empty",
    },
    warnings: unwrapped.warnings,
  };
}

function decodeExtendedCardResources(bytes) {
  const hasDirectFf21Wrapper = bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0x21 && bytes[2] <= bytes.length - 3;
  const unwrapped = hasDirectFf21Wrapper
    ? {
        rawTlv: bytesToSpacedHex(bytes.slice(0, 3 + bytes[2])),
        valueBytes: bytes.slice(3, 3 + bytes[2]),
        warnings: [],
      }
    : unwrapIfTagged(bytes, "FF21");
  const inner = parseBerTlv(unwrapped.valueBytes);
  const fields = [
    field("Tag", "0xFF21"),
    field("Object", "Extended Card Resources Information"),
    field("Response bytes", bytesToSpacedHex(bytes)),
    ...(unwrapped.rawTlv ? [field("Wrapped TLV", unwrapped.rawTlv)] : []),
  ];
  const decodedFields = {
    getDataTagReference: "0xFF21",
    getDataObjectName: "Extended Card Resources Information",
  };
  const knownStandardTags = {
    "81": "Number of installed applications",
    "82": "Free non volatile memory",
    "83": "Free volatile memory",
  };

  for (const item of inner.items) {
    const semanticLabel = knownStandardTags[item.tagHex] || `Inner tag ${item.tagHex}`;
    let semanticValue = bytesToHex(item.valueBytes);
    if (item.tagHex === "81" || item.tagHex === "82" || item.tagHex === "83") {
      let numericValue = 0;
      for (const byteValue of item.valueBytes) {
        numericValue = (numericValue << 8) | byteValue;
      }
      semanticValue = item.tagHex === "81" ? String(numericValue) : `${numericValue} byte(s)`;
      if (item.tagHex === "81") {
        decodedFields.installedApplications = numericValue;
      } else if (item.tagHex === "82") {
        decodedFields.freeNonVolatileMemory = numericValue;
      } else if (item.tagHex === "83") {
        decodedFields.freeVolatileMemory = numericValue;
      }
    }
    fields.push(field(`${semanticLabel} TLV`, item.tlvSpacedHex || item.tlvHex));
    fields.push(field(semanticLabel, semanticValue, {
      certainty: knownStandardTags[item.tagHex] ? "confirmed" : "possible",
    }));
  }

  const warnings = [...unwrapped.warnings, ...inner.warnings.map((message) => warning(message))];
  if (inner.items.some((item) => !knownStandardTags[item.tagHex])) {
    warnings.push(
      warning(
        "FF21 was recognized as Extended Card Resources Information, but one or more inner tags are not the standard ETSI 102 226 81/82/83 set. Inner tags are shown structurally without guessed semantics.",
        "info",
      ),
    );
  }

  return {
    sections: [section("GET DATA response", fields)],
    decodedFields,
    warnings,
  };
}

function isCanonicalStandaloneFf21(bytes) {
  if (!(bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0x21)) {
    return false;
  }
  const declaredLength = bytes[2];
  if (declaredLength !== bytes.length - 3) {
    return false;
  }
  const inner = parseBerTlv(bytes.slice(3));
  if (!inner.isComplete || inner.warnings.length) {
    return false;
  }
  if (!inner.items.length) {
    return false;
  }
  return inner.items.every((item) => ["81", "82", "83"].includes(item.tagHex));
}

function decodeGetDataByTag(tagReference, bytes) {
  switch (tagReference) {
    case "0x9F7F":
      return decodeCplc(bytes);
    case "0x0066":
      return decodeCardRecognition(bytes);
    case "0x00E0":
      return decodeKeyInformationTemplate(bytes);
    case "0x00C1":
      return decodeSequenceCounter(bytes);
    case "0xFF21":
      return decodeExtendedCardResources(bytes);
    default: {
      const ber = parseBerTlv(bytes);
      return {
        sections: [
          section("GET DATA response", [
            field("Tag", tagReference),
            field("Object", GET_DATA_TAG_NAMES[tagReference] || "GET DATA object"),
            field("Response bytes", bytesToSpacedHex(bytes)),
            field("BER-TLV items", ber.items.length),
          ]),
        ],
        decodedFields: {
          getDataTagReference: tagReference,
          getDataObjectName: GET_DATA_TAG_NAMES[tagReference] || "GET DATA object",
          tlvItems: ber.items.length,
        },
        warnings: ber.warnings.map((message) => warning(message)),
      };
    }
  }
}

export function createCommandContext(result) {
  if (!result || result.kind !== "command-apdu") {
    return null;
  }
  if (result.commandName === "GET DATA") {
    return {
      commandName: result.commandName,
      tagReference: result.decodedFields.tagReference,
      claValue: result.cla?.value ?? null,
      layer: result.layer,
    };
  }
  return {
    commandName: result.commandName,
    claValue: result.cla?.value ?? null,
    layer: result.layer,
  };
}

export function decodeGetDataResponse(bytes, previousCommandContext) {
  if (!previousCommandContext || previousCommandContext.commandName !== "GET DATA" || !previousCommandContext.tagReference) {
    return null;
  }
  const decoded = decodeGetDataByTag(previousCommandContext.tagReference, bytes);
  return {
    commandName: "GET DATA response",
    category: "Data management response",
    layer:
      previousCommandContext.claValue !== null && (previousCommandContext.claValue & 0x80) === 0x80
        ? "GlobalPlatform GET DATA response layer"
        : "ISO/ETSI GET DATA response layer",
    confidence: "possible",
    shortMeaning: `Response data decoded using the previous GET DATA request tag ${previousCommandContext.tagReference}.`,
    possibleSpecArea:
      previousCommandContext.claValue !== null && (previousCommandContext.claValue & 0x80) === 0x80
        ? "GlobalPlatform Card Specification / GET DATA response data"
        : "ISO/IEC 7816-4 / ETSI TS 102 221 GET DATA response data",
    sections: decoded.sections,
    decodedFields: decoded.decodedFields,
    warnings: decoded.warnings,
  };
}

export function decodePotentialGetDataPayload(bytes) {
  if (isCanonicalStandaloneFf21(bytes)) {
    const decoded = decodeExtendedCardResources(bytes);
    return {
      commandName: "GET DATA response",
      category: "Data management response",
      layer: "Context-inferred GET DATA response layer",
      confidence: "possible",
      shortMeaning: "Canonical FF21 object recognized without an explicit preceding GET DATA command.",
      possibleSpecArea: "GlobalPlatform Card Specification / GET DATA response data",
      sections: decoded.sections,
      decodedFields: decoded.decodedFields,
      warnings: decoded.warnings,
    };
  }

  const ber = parseBerTlv(bytes);
  const topTag = ber.items[0]?.tagHex || null;
  if (!topTag || !["66", "E0", "C1", "9F7F"].includes(topTag)) {
    if (!(topTag === "FF21")) {
      return null;
    }
  }
  if (topTag === "FF21") {
    return {
      commandName: "Potential GET DATA response",
      category: "Potential data management response",
      layer: "Context-aware GET DATA response helper",
      confidence: "possible",
      shortMeaning: "Potential GET DATA response / BER-TLV response data — context required for exact decoding.",
      possibleSpecArea: "GlobalPlatform or ISO/ETSI GET DATA response data",
      sections: [
        section("Potential GET DATA response", [
          field("Top-level tag", "0xFF21"),
          field("Potential object", "Extended Card Resources Information"),
          field("Payload bytes", bytesToSpacedHex(bytes)),
          field("BER-TLV items", ber.items.length),
        ]),
      ],
      decodedFields: {
        potentialGetDataTopTag: "0xFF21",
      },
      warnings: [...ber.warnings.map((message) => warning(message)), warning("Potential GET DATA response / BER-TLV response data — context required for exact decoding.", "info")],
    };
  }
  return {
    commandName: "Potential GET DATA response",
    category: "Potential data management response",
    layer: "Context-aware GET DATA response helper",
    confidence: "possible",
    shortMeaning: "Potential GET DATA response / BER-TLV response data — context required for exact decoding.",
    possibleSpecArea: "GlobalPlatform or ISO/ETSI GET DATA response data",
    sections: [
      section("Potential GET DATA response", [
        field("Top-level tag", `0x${topTag}`),
        field("Payload bytes", bytesToSpacedHex(bytes)),
        field("BER-TLV items", ber.items.length),
      ]),
    ],
    decodedFields: {
      potentialGetDataTopTag: `0x${topTag}`,
    },
    warnings: [...ber.warnings.map((message) => warning(message)), warning("Potential GET DATA response / BER-TLV response data — context required for exact decoding.", "info")],
  };
}
