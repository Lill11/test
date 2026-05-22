import { field, section, warning } from "../../core/format.js";
import { bytesToSpacedHex } from "../../core/hex.js";
import { parseBerTlv } from "../../core/tlv.js";
import { addCommonApduSection } from "../shared.js";

const MANAGE_LSI_OPERATION_MAP = {
  0x00: "Select LSI",
  0x01: "Reset LSE",
  0x02: "Assign SWP",
  0x03: "Retrieve SWP",
  0x04: "Configure LSIs",
};

const MEP_MODE_MAP = {
  0x00: "No jointly supported MEP mode",
  0x01: "MEP-A1",
  0x02: "MEP-A2",
  0x03: "MEP-B",
};

function decodeLsiOptions(byteValue) {
  return byteValue & 0x01
    ? "LSI indication via NAD byte supported / used"
    : "LSI indication via NAD byte not supported / not used";
}

function decodeMepMode(byteValue) {
  return MEP_MODE_MAP[byteValue] || `Unknown / RFU MEP mode 0x${byteValue.toString(16).toUpperCase().padStart(2, "0")}`;
}

function decodeMepModeList(bytes) {
  return bytes.map((byteValue) => decodeMepMode(byteValue));
}

function knownTagMeaning(tagHex) {
  return {
    "80": "Highest LSI / ATR / assigned SWP LSI",
    "81": "LSI options",
    "90": "SGP.22 MEP mode information",
    "91": "SGP.22 maximum LSIs for enabled profiles",
  }[tagHex] || "Unknown / proprietary LSI TLV";
}

function makeTlvFields(item, label) {
  return [
    field(`${label} TLV`, item.tlvSpacedHex || item.tlvHex),
    field(`${label} tag`, `0x${item.tagHex}`),
    field(`${label} length`, `${item.length} byte(s)`),
    field(`${label} value`, item.valueHex ? bytesToSpacedHex(item.valueBytes) : "Empty"),
  ];
}

function decodeConfigureLsiPayload(bytes, mode) {
  const ber = parseBerTlv(bytes);
  if (!ber.items.length || !ber.isComplete) {
    return {
      sections: [
        section(mode === "command" ? "Configure LSIs payload" : "MANAGE LSI response payload", [
          field("Payload bytes", bytesToSpacedHex(bytes) || "None"),
        ]),
      ],
      decodedFields: {},
      warnings: [
        warning("MANAGE LSI payload is present but could not be fully parsed as BER-TLV; raw bytes were preserved."),
        ...ber.warnings.map((message) => warning(message)),
      ],
    };
  }

  const warnings = [];
  const fields = [field("Payload bytes", bytesToSpacedHex(bytes) || "None"), field("TLV items", ber.items.length)];
  const decodedFields = {};
  const remainingTagSet = new Set();

  for (const item of ber.items) {
    remainingTagSet.add(item.tagHex);
    if (!["80", "81", "90", "91"].includes(item.tagHex)) {
      warnings.push(warning(`MANAGE LSI payload contains unsupported TLV tag 0x${item.tagHex}; decoded as raw TLV only.`));
    }
  }

  for (const item of ber.items) {
    if (item.tagHex === "80" && item.length === 1) {
      if (mode === "command") {
        fields.push(...makeTlvFields(item, "Highest proposed LSI"));
        fields.push(field("Highest proposed LSI meaning", item.valueBytes[0]));
        decodedFields.highestProposedLsi = item.valueBytes[0];
      } else {
        fields.push(...makeTlvFields(item, "Highest supported LSI"));
        fields.push(field("Highest supported LSI meaning", item.valueBytes[0]));
        decodedFields.highestSupportedLsi = item.valueBytes[0];
      }
      continue;
    }

    if (item.tagHex === "81" && item.length === 1) {
      const meaning = decodeLsiOptions(item.valueBytes[0]);
      fields.push(...makeTlvFields(item, mode === "command" ? "LSI options supported by terminal" : "LSI options for card session"));
      fields.push(field("LSI options meaning", meaning));
      decodedFields.lsiOptions = item.valueHex;
      decodedFields.lsiOptionsMeaning = meaning;
      continue;
    }

    if (item.tagHex === "90" && item.length >= 1) {
      if (mode === "command") {
        const modes = decodeMepModeList(item.valueBytes);
        fields.push(...makeTlvFields(item, "Device MEP modes"));
        fields.push(field("Device MEP mode priority", modes.join(" -> ")));
        decodedFields.deviceMepModes = modes.join(", ");
      } else {
        const jointlySupportedMode = decodeMepMode(item.valueBytes[0]);
        const euiccModes = decodeMepModeList(item.valueBytes.slice(1));
        fields.push(...makeTlvFields(item, "Joint MEP mode information"));
        fields.push(field("Jointly supported MEP mode", jointlySupportedMode));
        fields.push(field("All eUICC-supported MEP modes", euiccModes.length ? euiccModes.join(", ") : "None listed"));
        decodedFields.jointlySupportedMepMode = jointlySupportedMode;
        decodedFields.euiccSupportedMepModes = euiccModes.join(", ") || "None listed";
      }
      continue;
    }

    if (item.tagHex === "91" && item.length === 1) {
      const value = item.valueBytes[0];
      fields.push(...makeTlvFields(item, mode === "command" ? "Maximum enabled-profile LSIs proposed by device" : "Jointly supported enabled-profile LSIs"));
      fields.push(
        field(
          mode === "command" ? "Maximum enabled-profile LSIs proposed by device" : "Jointly supported enabled-profile LSIs",
          value,
        ),
      );
      if (mode === "command") {
        decodedFields.maxEnabledProfileLsis = value;
      } else {
        decodedFields.jointlySupportedEnabledProfileLsis = value;
      }
      continue;
    }

    if (item.tagHex === "80" && item.length > 1 && mode === "response") {
      fields.push(...makeTlvFields(item, "ATR"));
      fields.push(field("ATR bytes", bytesToSpacedHex(item.valueBytes)));
      decodedFields.atr = item.valueHex;
      continue;
    }

    fields.push(...makeTlvFields(item, knownTagMeaning(item.tagHex)));
  }

  if (mode === "response") {
    decodedFields.manageLsiResponseType = "Configure LSIs response";
  }

  return {
    sections: [section(mode === "command" ? "Configure LSIs payload" : "MANAGE LSI response payload", fields)],
    decodedFields,
    warnings,
  };
}

export function decodeManageLsiCommand(apdu) {
  const operation = MANAGE_LSI_OPERATION_MAP[apdu.p1] || `Unknown / RFU LSI operation 0x${apdu.p1Hex}`;
  const warnings = [];
  const sections = [
    section("LSI control", [
      field("Operation", operation, {
        certainty: MANAGE_LSI_OPERATION_MAP[apdu.p1] ? "confirmed" : "possible",
      }),
      field("LSI number (P2)", `0x${apdu.p2Hex}`),
      field("Control payload length", apdu.lc ?? 0),
      field("Control payload", apdu.data.spacedHex || "None"),
    ]),
  ];

  if (apdu.p1 === 0x04) {
    if (apdu.p2 !== 0x00) {
      warnings.push(warning("Configure LSIs expects P2=0x00 per ETSI TS 102 221; this APDU uses a different value."));
    }
    if (apdu.lc === null || !apdu.data.bytes.length) {
      warnings.push(warning("Configure LSIs should carry TLV command data, but no data field is present."));
    } else {
      const payload = decodeConfigureLsiPayload(apdu.data.bytes, "command");
      sections.push(...payload.sections);
      warnings.push(...payload.warnings);
    }
    if (apdu.le !== 0) {
      warnings.push(warning("Configure LSIs normally expects Le=0x00 so the card can return the negotiated LSI configuration."));
    }
  }

  if (apdu.p1 === 0x03 && apdu.p2 !== 0x00) {
    warnings.push(warning("Retrieve SWP expects P2=0x00 per ETSI TS 102 221."));
  }

  if ((apdu.p1 === 0x01 || apdu.p1 === 0x02 || apdu.p1 === 0x03) && apdu.le !== 0) {
    warnings.push(warning("Reset LSE, Assign SWP, and Retrieve SWP normally expect Le=0x00."));
  }

  if (apdu.p1 === 0x00 && (apdu.lc !== null || apdu.le !== null)) {
    warnings.push(warning("Select LSI normally omits both Lc and Le."));
  }

  addCommonApduSection(apdu, sections);
  return {
    sections,
    warnings,
    decodedFields: {
      operation,
      lsiReference: `0x${apdu.p2Hex}`,
      ...(apdu.p1 === 0x04 && apdu.data.bytes.length ? decodeConfigureLsiPayload(apdu.data.bytes, "command").decodedFields : {}),
    },
  };
}

export function decodeManageLsiPayload(bytes) {
  const ber = parseBerTlv(bytes);
  if (!ber.items.length || !ber.isComplete) {
    return null;
  }

  const tags = ber.items.map((item) => item.tagHex);
  if (!tags.every((tagHex) => ["80", "81", "90", "91"].includes(tagHex))) {
    return null;
  }

  if (ber.items.length === 1 && ber.items[0].tagHex === "80" && ber.items[0].length > 1) {
    const item = ber.items[0];
    return {
      commandName: "MANAGE LSI response",
      category: "eUICC / LSI response",
      layer: "ETSI TS 102 221 UICC layer",
      confidence: "possible",
      shortMeaning: "Payload looks like a MANAGE LSI reset-LSE or assign-SWP response carrying an ATR.",
      possibleSpecArea: "ETSI TS 102 221 / MANAGE LSI ATR response data",
      sections: [
        section("MANAGE LSI response payload", [
          ...makeTlvFields(item, "ATR"),
          field("Response type", "Reset LSE / Assign SWP response"),
          field("ATR bytes", bytesToSpacedHex(item.valueBytes)),
        ]),
      ],
      decodedFields: {
        manageLsiResponseType: "Reset LSE / Assign SWP response",
        atr: item.valueHex,
      },
      warnings: [],
    };
  }

  if (ber.items.length === 1 && ber.items[0].tagHex === "80" && ber.items[0].length === 1) {
    const item = ber.items[0];
    return {
      commandName: "MANAGE LSI response",
      category: "eUICC / LSI response",
      layer: "ETSI TS 102 221 UICC layer",
      confidence: "possible",
      shortMeaning: "Payload looks like a MANAGE LSI retrieve-SWP response carrying the assigned LSI.",
      possibleSpecArea: "ETSI TS 102 221 / MANAGE LSI retrieve SWP response data",
      sections: [
        section("MANAGE LSI response payload", [
          ...makeTlvFields(item, "Assigned SWP LSI"),
          field("Response type", item.valueBytes[0] === 0xff ? "Retrieve SWP response: no LSI assigned" : "Retrieve SWP response"),
          field("Assigned LSI", item.valueBytes[0] === 0xff ? "None assigned (0xFF)" : item.valueBytes[0]),
        ]),
      ],
      decodedFields: {
        manageLsiResponseType: "Retrieve SWP response",
        assignedSwpLsi: item.valueBytes[0] === 0xff ? "None assigned (0xFF)" : item.valueBytes[0],
      },
      warnings: [warning("Without the matching command context, a single 80 01 xx TLV could also be a minimal Configure LSIs response.")],
    };
  }

  const payload = decodeConfigureLsiPayload(bytes, "response");
  return {
    commandName: "MANAGE LSI response",
    category: "eUICC / LSI response",
    layer: "ETSI TS 102 221 UICC layer",
    confidence: "possible",
    shortMeaning: "Payload matches MANAGE LSI configuration data, including SGP.22 MEP-related TLVs when present.",
    possibleSpecArea: "ETSI TS 102 221 / MANAGE LSI configure LSIs response data",
    sections: payload.sections,
    decodedFields: payload.decodedFields,
    warnings: payload.warnings,
  };
}
