import { bytesToHex, bytesToSpacedHex, toHex } from "../core/hex.js";
import { field, section, warning } from "../core/format.js";
import { parseBerTlv, parseBerTlvPrefix } from "../core/tlv.js";

// Source: ISO/IEC 7816-4 file/application selection response templates;
// ETSI TS 102 221 reuses FCP/FCI/FMD on the UICC-terminal interface.
const TEMPLATE_NAMES = {
  "62": "FCP template",
  "64": "FMD template",
  "6F": "FCI template",
};

// Source: common UICC/SIM file identifiers from ETSI TS 102 221 / 3GPP file-system conventions.
// This is intentionally a curated subset for stable naming, not a complete FID registry.
const FILE_ID_NAMES = {
  "2F05": "EF_PL",
  "2F06": "EF_ARR",
  "2F00": "EF_DIR",
  "2FE2": "EF_ICCID",
  "3F00": "MF",
  "6F07": "EF_IMSI",
  "6F38": "EF_SST / EF_UST family",
  "6F3A": "EF_ADN",
  "6F46": "EF_SPN",
  "6FAD": "EF_AD",
  "7F10": "DF_TELECOM",
  "7F20": "DF_GSM",
};

// Source: common application/security-domain AIDs from 3GPP USIM/ISIM and
// GSMA/GlobalPlatform eUICC security-domain usage. Curated subset only.
const AID_PREFIXES = [
  { prefix: "A0000000871002", name: "USIM ADF", family: "3GPP USIM / ADF.USIM", layer: "ETSI TS 102 221 UICC SELECT response layer" },
  { prefix: "A0000000871004", name: "ISIM ADF", family: "3GPP ISIM / ADF.ISIM", layer: "ETSI TS 102 221 UICC SELECT response layer" },
  { prefix: "A0000005591010FFFFFFFF8900000100", name: "ISD-R", family: "GSMA eUICC ISD-R", layer: "GlobalPlatform / eUICC SELECT response layer" },
  { prefix: "A0000005591010FFFFFFFF8900000200", name: "ECASD", family: "GSMA eUICC ECASD", layer: "GlobalPlatform / eUICC SELECT response layer" },
  { prefix: "A000000151000000", name: "Card Manager / Security Domain", family: "GlobalPlatform Security Domain", layer: "GlobalPlatform / eUICC SELECT response layer" },
];

// Source: ISO/IEC 7816-4 FCP/FCI/FMD tags plus ETSI TS 102 221 UICC-specific objects.
const TOP_LEVEL_TAG_NAMES = {
  "80": "File size",
  "81": "Total file size",
  "82": "File Descriptor",
  "83": "File Identifier",
  "84": "DF Name / AID",
  "88": "Short File Identifier",
  "8A": "Life Cycle Status Integer",
  "A5": "Proprietary information",
  "AB": "Security attributes",
  "C6": "PIN Status Template DO",
};

// Source: GlobalPlatform FCI proprietary template / ETSI TS 102 221 UICC proprietary information.
const PROPRIETARY_TAG_NAMES = {
  "80": "UICC characteristics",
  "81": "Application power consumption",
  "82": "Minimum application clock frequency",
  "83": "Amount of available memory",
  "84": "File details",
  "85": "Reserved file size",
  "86": "Maximum file size",
  "87": "Supported system commands",
  "73": "Security Domain Management Data",
  "9F65": "Maximum command data field length",
  "9F6E": "Application production life cycle data",
};

// Source: GlobalPlatform Security Domain Management Data discretionary objects.
const SECURITY_DOMAIN_MANAGEMENT_TAG_NAMES = {
  "06": "Object Identifier",
  "60": "Card management type and version",
  "63": "Card identification scheme",
  "64": "Secure channel protocol of the selected Security Domain",
  "65": "Card configuration details",
  "66": "Card or Security Domain data",
};

// Source: ETSI TS 102 221 security attribute data objects used in FCP/ARR-related structures.
const SECURITY_TAG_NAMES = {
  "80": "AM_DO / Access Mode",
  "81": "Security condition DO - always",
  "82": "Security condition DO - never",
  "83": "Key reference / ARR record number",
  "84": "Security environment reference",
  "86": "Security condition byte",
  "8B": "Expanded security attribute - compact format",
  "8C": "Expanded security attribute",
  "8D": "Security attribute coding reference",
  "95": "Usage qualifier / ARR reference",
  "A4": "Security attribute template",
};

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

function identifyFileId(fileIdHex) {
  return FILE_ID_NAMES[fileIdHex] || null;
}

function identifyAid(aidHex) {
  return AID_PREFIXES.find((entry) => aidHex.startsWith(entry.prefix)) || null;
}

function decodeLifecycleStatus(byteValue) {
  if (byteValue === 0x00) {
    return "No information given";
  }
  if (byteValue === 0x01) {
    return "Creation state";
  }
  if (byteValue === 0x03) {
    return "Initialization state";
  }
  if ((byteValue & 0x07) === 0x05) {
    return "Operational state - activated";
  }
  if ((byteValue & 0x07) === 0x04) {
    return "Operational state - deactivated";
  }
  if ((byteValue & 0x18) === 0x18) {
    return "Termination state";
  }
  if ((byteValue & 0x80) !== 0) {
    return "Proprietary life cycle value";
  }
  return `RFU / unmapped life cycle value 0x${toHex(byteValue)}`;
}

function decodeFileDescriptor(item) {
  if (item.valueBytes.length < 2) {
    return {
      fields: [field("File Descriptor", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`)],
      warnings: ["File Descriptor DO should contain at least 2 value byte(s)."],
      summary: {},
    };
  }

  const descriptorByte = item.valueBytes[0];
  const dataCodingByte = item.valueBytes[1];
  const shareable = (descriptorByte & 0x40) !== 0 ? "Shareable file" : "Not shareable file";

  let fileType = `Raw descriptor 0x${toHex(descriptorByte)}`;
  if ((descriptorByte & 0x38) === 0x38) {
    fileType = "DF or ADF";
  } else if ((descriptorByte & 0x07) === 0x01) {
    fileType = "Transparent EF";
  } else if ((descriptorByte & 0x07) === 0x02) {
    fileType = "Linear fixed EF";
  } else if ((descriptorByte & 0x07) === 0x06) {
    fileType = "Cyclic EF";
  }

  const fields = [
    field("File Descriptor TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
    field("Descriptor byte", `0x${toHex(descriptorByte)}`),
    field("File type / structure", fileType, {
      certainty: fileType.startsWith("Raw descriptor") ? "possible" : "confirmed",
    }),
    field("Accessibility", shareable, { certainty: "confirmed" }),
    field("Data coding byte", `0x${toHex(dataCodingByte)}`),
  ];

  let recordLength = null;
  let numberOfRecords = null;
  if (item.valueBytes.length >= 5) {
    recordLength = (item.valueBytes[2] << 8) | item.valueBytes[3];
    numberOfRecords = item.valueBytes[4];
    fields.push(field("Record length", `${recordLength} byte(s)`));
    fields.push(field("Number of records", numberOfRecords));
  }

  return {
    fields,
    summary: {
      fileDescriptorType: fileType,
      fileShareability: shareable,
      recordLength: recordLength ?? "Not present",
      numberOfRecords: numberOfRecords ?? "Not present",
    },
  };
}

function decodeFileIdentifier(item) {
  const fileIdHex = bytesToHex(item.valueBytes);
  const knownName = identifyFileId(fileIdHex);
  return {
    fields: [
      field("File Identifier TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("File Identifier", fileIdHex || "Empty"),
      field("Known file name", knownName || "No common name mapped", {
        certainty: knownName ? "confirmed" : "possible",
      }),
    ],
    summary: {
      fileId: fileIdHex || "Not present",
      fileName: knownName || "Not mapped",
    },
  };
}

function decodeDfName(item) {
  const aidHex = bytesToHex(item.valueBytes);
  const knownAid = identifyAid(aidHex);
  return {
    fields: [
      field("DF Name / AID TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("DF Name / AID", aidHex || "Empty"),
      field("Identified application", knownAid ? knownAid.name : "Unknown AID / DF name", {
        certainty: knownAid ? "confirmed" : "possible",
      }),
      field("Context family", knownAid ? knownAid.family : "Generic DF / application selection", {
        certainty: knownAid ? "confirmed" : "possible",
      }),
    ],
    summary: {
      aid: aidHex || "Not present",
      identifiedApplication: knownAid?.name || "Unknown AID / DF name",
      identifiedLayer: knownAid?.layer || "ETSI TS 102 221 UICC SELECT response layer",
    },
  };
}

function decodeSimpleNumeric(item, label) {
  let value = 0;
  for (const byteValue of item.valueBytes) {
    value = (value << 8) | byteValue;
  }
  return {
    fields: [
      field(`${label} TLV`, `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field(label, `${value} byte(s)`),
    ],
    summary: {
      [label === "File size" ? "fileSize" : "totalFileSize"]: value,
    },
  };
}

function decodeHexFlagBytes(item, label, note) {
  return {
    fields: [
      field(`${label} TLV`, `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field(label, item.valueHex || "empty", {
        certainty: "possible",
        note,
      }),
    ],
    summary: {},
  };
}

function decodeSfi(item) {
  const raw = item.valueBytes[0];
  const sfi = raw >> 3;
  return {
    fields: [
      field("Short File Identifier TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("Short File Identifier", `0x${toHex(sfi)}`, {
        certainty: "confirmed",
      }),
    ],
    summary: {
      shortFileIdentifier: `0x${toHex(sfi)}`,
    },
  };
}

function decodePsDoByte(byteValue, pinReferences, fields) {
  const bitLabels = ["b8", "b7", "b6", "b5", "b4", "b3", "b2", "b1"];
  if (!pinReferences.length) {
    return {
      pinStateSummary: `PS_DO raw value 0x${toHex(byteValue)} with no PIN reference DOs following it.`,
    };
  }

  const pinStates = [];
  for (let index = 0; index < pinReferences.length; index += 1) {
    const bitIndex = 7 - index;
    const enabled = ((byteValue >> bitIndex) & 0x01) === 1;
    const reference = pinReferences[index];
    pinStates.push(`${reference} = ${enabled ? "enabled" : "disabled"}`);
    fields.push(
      field(`${reference} state`, enabled ? "enabled" : "disabled", {
        certainty: "possible",
        note: `Derived from PS_DO ${bitLabels[index]} in listed PIN-reference order.`,
      }),
    );
  }

  return {
    pinStateSummary: pinStates.join("; "),
  };
}

function decodePinStatusTemplate(item) {
  const nested = parseBerTlv(item.valueBytes);
  const warnings = [...nested.warnings.map((message) => warning(message))];
  const fields = [
    field("PIN Status Template TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
  ];
  const pendingPsDo = [];
  const pendingUsageQualifiers = [];
  const pinReferences = [];
  for (const nestedItem of nested.items) {
    if (nestedItem.tagHex === "90") {
      pendingPsDo.push(...nestedItem.valueBytes);
      fields.push(field("PIN state bitmap TLV", `${nestedItem.tlvSpacedHex} (${nestedItem.tlvBytes.length} byte(s))`, {
        certainty: "confirmed",
      }));
      fields.push(field("PIN state bitmap raw value", nestedItem.valueHex || "empty", {
        certainty: "possible",
        note: "PS_DO bytes from ETSI TS 102 221. A set bit indicates the corresponding listed PIN reference is enabled.",
      }));
    } else if (nestedItem.tagHex === "95") {
      pendingUsageQualifiers.push(nestedItem.valueHex || "empty");
      fields.push(field("Usage qualifier raw value", nestedItem.valueHex || "empty", {
        certainty: "possible",
        note: "Indicates whether the following PIN reference is used for verification in this DF/ADF context.",
      }));
    } else if (nestedItem.tagHex === "83") {
      const reference = nestedItem.valueBytes.length ? `PIN 0x${toHex(nestedItem.valueBytes[0])}` : "Empty PIN reference";
      pinReferences.push(reference);
      fields.push(field("PIN reference", reference, { certainty: "confirmed" }));
    } else {
      fields.push(field(`PIN status nested tag 0x${nestedItem.tagHex}`, nestedItem.valueHex || "empty", { certainty: "possible" }));
    }
  }

  let pinStateSummary = "No PIN state bitmap present";
  if (pendingPsDo.length) {
    const decoded = decodePsDoByte(pendingPsDo[0], pinReferences, fields);
    pinStateSummary = decoded.pinStateSummary;
  }

  if (pendingUsageQualifiers.length && pinReferences.length) {
    const usageSummary = pinReferences
      .map((reference, index) => `${reference} usage qualifier = ${pendingUsageQualifiers[index] || "not present"}`)
      .join("; ");
    fields.push(field("PIN usage summary", usageSummary, {
      certainty: "possible",
    }));
  }

  return {
    fields,
    warnings,
    summary: {
      pinStatusReferences: pinReferences.join(", ") || "None listed",
      pinStateSummary,
    },
  };
}

function decodeNestedTemplate(item, label, tagNames = {}) {
  const nested = parseBerTlv(item.valueBytes);
  const warnings = [...nested.warnings.map((message) => warning(message))];
  const fields = [
    field(`${label} TLV`, `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
  ];

  for (const nestedItem of nested.items) {
    const nestedLabel = tagNames[nestedItem.tagHex] || `${label} tag 0x${nestedItem.tagHex}`;
    if (nestedItem.constructed) {
      fields.push(field(nestedLabel, nestedItem.tlvSpacedHex || nestedItem.tlvHex, {
        certainty: "possible",
      }));
      const deeper = decodeNestedTemplate(
        nestedItem,
        nestedLabel,
        nestedItem.tagHex === "73" ? SECURITY_DOMAIN_MANAGEMENT_TAG_NAMES : tagNames,
      );
      fields.push(...deeper.fields.slice(1));
      warnings.push(...deeper.warnings);
    } else {
      const nestedValue =
        nestedItem.tagHex === "06"
          ? decodeOid(nestedItem.valueBytes)
          : nestedItem.tagHex === "9F65"
            ? `${parseInt(nestedItem.valueHex || "0", 16)} byte(s)`
            : nestedItem.valueHex || "empty";
      fields.push(field(nestedLabel, nestedValue, {
        certainty: tagNames[nestedItem.tagHex] ? "confirmed" : "possible",
      }));
    }
  }

  return { fields, warnings };
}

function decodeSelectResponseInnerItem(item) {
  switch (item.tagHex) {
    case "80":
      return decodeSimpleNumeric(item, "File size");
    case "81":
      return decodeSimpleNumeric(item, "Total file size");
    case "82":
      return decodeFileDescriptor(item);
    case "83":
      return decodeFileIdentifier(item);
    case "84":
      return decodeDfName(item);
    case "88":
      return decodeSfi(item);
    case "8A": {
      const value = item.valueBytes[0];
      const lifecycle = decodeLifecycleStatus(value);
      return {
        fields: [
          field("Life Cycle Status TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
          field("Life Cycle Status Integer", `0x${toHex(value)}`),
          field("Life Cycle Status meaning", lifecycle, {
            certainty: lifecycle.startsWith("RFU") ? "possible" : "confirmed",
          }),
        ],
        summary: {
          lifeCycleStatus: `0x${toHex(value)}`,
          lifeCycleMeaning: lifecycle,
        },
      };
    }
    case "86":
      return decodeHexFlagBytes(
        item,
        "Security attributes (compact)",
        "Compact security-attribute bytes; interpretation depends on the selected file and access-rule context.",
      );
    case "A5":
      return decodeNestedTemplate(item, "Proprietary information", PROPRIETARY_TAG_NAMES);
    case "AB":
      return decodeNestedTemplate(item, "Security attributes", SECURITY_TAG_NAMES);
    case "C6":
      return decodePinStatusTemplate(item);
    default:
      return {
        fields: [
          field(TOP_LEVEL_TAG_NAMES[item.tagHex] || `Tag 0x${item.tagHex}`, `${item.valueHex || "empty"} (${item.length} byte(s))`, {
            certainty: TOP_LEVEL_TAG_NAMES[item.tagHex] ? "confirmed" : "possible",
          }),
        ],
        summary: {},
      };
  }
}

function determineSelectContext(summary, templateTag) {
  if (summary.identifiedLayer) {
    return {
      layer: summary.identifiedLayer,
      category: summary.identifiedLayer.includes("GlobalPlatform") ? "GlobalPlatform / eUICC selection response" : "UICC file selection response",
      possibleSpecArea: summary.identifiedLayer.includes("GlobalPlatform")
        ? "GlobalPlatform / eUICC SELECT response data"
        : "ETSI TS 102 221 / ISO 7816 SELECT response data",
    };
  }

  if (templateTag === "6F" && summary.aid) {
    return {
      layer: "ISO / ETSI SELECT response layer",
      category: "Application selection response",
      possibleSpecArea: "ISO/IEC 7816-4 SELECT FCI response data",
    };
  }

  return {
    layer: "ETSI TS 102 221 UICC SELECT response layer",
    category: "File selection response",
    possibleSpecArea: "ETSI TS 102 221 / ISO 7816 SELECT response data",
  };
}

function determineFileManagementContext(templateTag, summary) {
  if (summary.identifiedApplication && summary.identifiedApplication !== "Unknown AID / DF name") {
    return "Application-selection response, typically after SELECT by DF name / AID.";
  }
  if (summary.fileId || summary.fileName && summary.fileName !== "Not mapped") {
    return "File-management response seen after SELECT, STATUS, or GET RESPONSE when FCP/FMD data is requested.";
  }
  if (templateTag === "64") {
    return "File-management descriptor data, often returned by SELECT or STATUS when FMD is requested.";
  }
  return "Structured file-management response that commonly follows SELECT, STATUS, or GET RESPONSE.";
}

export function decodeSelectResponsePayload(bytes) {
  if (!bytes.length) {
    return null;
  }

  const prefix = parseBerTlvPrefix(bytes);
  const templateTag = prefix.tagHex;
  if (!["62", "64", "6F"].includes(templateTag)) {
    return null;
  }

  const ber = parseBerTlv(bytes);
  const outer = ber.items[0];
  const warnings = [...ber.warnings.map((message) => warning(message))];

  const templateName = TEMPLATE_NAMES[templateTag];
  const innerBytes = outer ? outer.valueBytes : prefix.availableValueBytes || [];
  const inner = parseBerTlv(innerBytes);
  warnings.push(...inner.warnings.map((message) => warning(message)));
  if (!prefix.isComplete) {
    warnings.push(warning(`Top-level ${templateName} is truncated; ${prefix.missingValueBytes} byte(s) are still missing from the declared length.`, "warning"));
  }

  const fields = [
    field("Template", templateName),
    field("Top-level tag", `0x${templateTag}`),
    field("Payload bytes", bytesToSpacedHex(bytes)),
  ];
  const decodedTree = [];
  const summary = {};

  for (const item of inner.items) {
    const decoded = decodeSelectResponseInnerItem(item);
    decodedTree.push(...decoded.fields);
    Object.assign(summary, decoded.summary || {});
    for (const currentWarning of decoded.warnings || []) {
      warnings.push(currentWarning);
    }
  }

  const context = determineSelectContext(summary, templateTag);
  const fileManagementContext = determineFileManagementContext(templateTag, summary);
  const selectedTarget =
    summary.fileName && summary.fileName !== "Not mapped"
      ? summary.fileName
      : summary.identifiedApplication && summary.identifiedApplication !== "Unknown AID / DF name"
        ? summary.identifiedApplication
        : templateName === "FCI template"
          ? "Selected application or DF"
          : "Selected file";

  return {
    commandName: `SELECT response (${templateName})`,
    category: context.category,
    layer: context.layer,
    confidence: "confirmed",
    shortMeaning: `Structured ${templateName} from a file-management response, commonly after SELECT and sometimes after STATUS or GET RESPONSE.`,
    possibleSpecArea: context.possibleSpecArea,
    sections: [
      section("SELECT response overview", [
        ...fields,
        field("Selected target", selectedTarget, {
          certainty: selectedTarget === "Selected file" || selectedTarget === "Selected application or DF" ? "possible" : "confirmed",
        }),
        field("Likely command family", fileManagementContext, {
          certainty: "possible",
        }),
        ...(summary.fileId ? [field("File Identifier", summary.fileId)] : []),
        ...(summary.aid ? [field("Application / DF name", summary.aid)] : []),
      ]),
      section(`${templateName} TLV tree`, decodedTree.length ? decodedTree : [field("TLVs", "No nested TLV items decoded", { certainty: "possible" })]),
    ],
    decodedFields: {
      selectResponseTemplate: templateName,
      selectedFile: summary.fileName || "Not identified",
      fileIdentifier: summary.fileId || "Not present",
      selectedAid: summary.aid || "Not present",
      identifiedApplication: summary.identifiedApplication || "Not identified",
      fileManagementContext,
      fileDescriptorType: summary.fileDescriptorType || "Not decoded",
      fileShareability: summary.fileShareability || "Not decoded",
      recordLength: summary.recordLength || "Not present",
      numberOfRecords: summary.numberOfRecords || "Not present",
      lifeCycleStatus: summary.lifeCycleStatus || "Not present",
      lifeCycleMeaning: summary.lifeCycleMeaning || "Not present",
      shortFileIdentifier: summary.shortFileIdentifier || "Not present",
      pinStatusReferences: summary.pinStatusReferences || "Not decoded",
      pinStateSummary: summary.pinStateSummary || "Not decoded",
    },
    warnings,
  };
}
