import { parseBerTlv, parseCatTlv } from "../../core/tlv.js";
import { field, section, warning } from "../../core/format.js";
import { addCommonApduSection } from "../shared.js";

export const proactiveCommandTypes = {
  0x01: "REFRESH",
  0x02: "MORE TIME",
  0x03: "POLL INTERVAL",
  0x04: "POLLING OFF",
  0x05: "SET UP EVENT LIST",
  0x10: "SET UP CALL",
  0x11: "SEND SS",
  0x12: "SEND USSD",
  0x13: "SEND SHORT MESSAGE",
  0x14: "SEND DTMF",
  0x15: "LAUNCH BROWSER",
  0x20: "PLAY TONE",
  0x21: "DISPLAY TEXT",
  0x22: "GET INKEY",
  0x23: "GET INPUT",
  0x24: "SELECT ITEM",
  0x25: "SET UP MENU",
  0x26: "PROVIDE LOCAL INFORMATION",
  0x27: "TIMER MANAGEMENT",
  0x28: "SET UP IDLE MODE TEXT",
  0x40: "OPEN CHANNEL",
  0x41: "CLOSE CHANNEL",
  0x42: "RECEIVE DATA",
  0x43: "SEND DATA",
};

export const catTagNames = {
  0x01: "Command details",
  0x02: "Device identities",
  0x03: "Result",
  0x04: "Duration",
  0x05: "Alpha identifier",
  0x06: "Address",
  0x0d: "Text string",
  0x0f: "Item",
  0x12: "File list",
  0x32: "Bearer description",
  0x35: "Bearer independent protocol / buffer size",
  0x36: "Channel data",
  0x37: "Channel data length",
  0x3c: "Channel status",
};

const deviceIdentities = {
  0x81: "UICC",
  0x82: "Terminal",
  0x83: "Network",
};

const durationUnits = {
  0x00: "minutes",
  0x01: "seconds",
  0x02: "tenths of seconds",
};

const resultMeanings = {
  0x00: "Command performed successfully",
  0x01: "Command performed with partial comprehension",
  0x02: "Command performed, missing information",
  0x03: "REFRESH performed with additional EF read",
  0x04: "Command performed successfully, but requested icon could not be displayed",
  0x05: "Command performed, modified by call control",
  0x20: "Terminal currently unable to process command",
  0x21: "Network currently unable to process command",
  0x22: "User did not accept the proactive command",
  0x30: "Command beyond terminal capability",
};

function decodeCommandDetails(item) {
  if (item.valueBytes.length < 3) {
    return { fields: [field("Command details", "TLV too short", { certainty: "possible" })], warnings: ["Command details TLV is shorter than 3 bytes."], summary: {} };
  }

  const [commandNumber, typeOfCommand, commandQualifier] = item.valueBytes;
  const proactiveCommandType = proactiveCommandTypes[typeOfCommand] || `0x${typeOfCommand.toString(16).toUpperCase().padStart(2, "0")}`;
  return {
    fields: [
      field("Command details TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("Command details value", `${item.valueHex} (${item.length} byte(s))`),
      field("Command number", commandNumber),
      field("Proactive command type", proactiveCommandType, {
        certainty: proactiveCommandTypes[typeOfCommand] ? "confirmed" : "possible",
      }),
      field("Command qualifier", `0x${commandQualifier.toString(16).toUpperCase().padStart(2, "0")}`),
    ],
    summary: {
      commandNumber,
      proactiveCommandType,
      commandQualifier,
    },
  };
}

function decodeDeviceIdentities(item) {
  if (item.valueBytes.length < 2) {
    return { fields: [field("Device identities", "TLV too short", { certainty: "possible" })], warnings: ["Device identities TLV is shorter than 2 bytes."] };
  }

  const sourceDevice = deviceIdentities[item.valueBytes[0]] || `0x${item.valueBytes[0].toString(16).toUpperCase().padStart(2, "0")}`;
  const destinationDevice = deviceIdentities[item.valueBytes[1]] || `0x${item.valueBytes[1].toString(16).toUpperCase().padStart(2, "0")}`;

  return {
    fields: [
      field("Device identities TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("Device identities value", `${item.valueHex} (${item.length} byte(s))`),
      field("Message direction", `${sourceDevice} -> ${destinationDevice}`, {
        certainty: deviceIdentities[item.valueBytes[0]] && deviceIdentities[item.valueBytes[1]] ? "confirmed" : "possible",
      }),
      field("Source device", sourceDevice, {
        certainty: deviceIdentities[item.valueBytes[0]] ? "confirmed" : "possible",
      }),
      field("Destination device", destinationDevice, {
        certainty: deviceIdentities[item.valueBytes[1]] ? "confirmed" : "possible",
      }),
    ],
  };
}

function decodeResult(item) {
  if (item.valueBytes.length < 1) {
    return { fields: [field("Result", "TLV too short", { certainty: "possible" })], warnings: ["Result TLV is empty."] };
  }

  const generalResult = item.valueBytes[0];
  const resultMeaning = resultMeanings[generalResult] || "Result code not yet mapped";

  return {
    fields: [
      field("Result TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("Result value", `${item.valueHex} (${item.length} byte(s))`),
      field("General result", `0x${generalResult.toString(16).toUpperCase().padStart(2, "0")}`),
      field("Meaning", resultMeaning, {
        certainty: resultMeanings[generalResult] ? "confirmed" : "possible",
      }),
      field("Additional info", item.valueBytes.length > 1 ? item.valueHex.slice(2) : "None", {
        certainty: item.valueBytes.length > 1 ? "confirmed" : "possible",
      }),
    ],
  };
}

function decodeDuration(item) {
  if (item.valueBytes.length < 2) {
    return { fields: [field("Duration", "TLV too short", { certainty: "possible" })], warnings: ["Duration TLV is shorter than 2 bytes."] };
  }

  const unit = durationUnits[item.valueBytes[0]] || `0x${item.valueBytes[0].toString(16).toUpperCase().padStart(2, "0")}`;
  return {
    fields: [
      field("Duration TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("Duration value", `${item.valueHex} (${item.length} byte(s))`),
      field("Time unit", unit, { certainty: durationUnits[item.valueBytes[0]] ? "confirmed" : "possible" }),
      field("Interval", item.valueBytes[1]),
      field("Meaning", `${item.valueBytes[1]} ${unit}`, {
        certainty: durationUnits[item.valueBytes[0]] ? "confirmed" : "possible",
      }),
    ],
    summary: {
      durationUnit: unit,
      durationInterval: item.valueBytes[1],
    },
  };
}

function decodeAlphaIdentifier(item) {
  const text = new TextDecoder("latin1").decode(Uint8Array.from(item.valueBytes));
  return {
    fields: [
      field("Alpha identifier TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("Alpha text", text || "(empty)", { certainty: text ? "possible" : "confirmed" }),
    ],
  };
}

function decodeAddress(item) {
  return {
    fields: [
      field("Address TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("TON/NPI", item.valueBytes.length ? `0x${item.valueBytes[0].toString(16).toUpperCase().padStart(2, "0")}` : "Not present"),
      field("Dialing digits", item.valueBytes.slice(1).map((byte) => byte.toString(16).toUpperCase().padStart(2, "0")).join(" ") || "None", {
        certainty: "possible",
      }),
    ],
  };
}

function decodeTextString(item) {
  if (!item.valueBytes.length) {
    return { fields: [field("Text string", "(empty)")], summary: {} };
  }
  const dcs = item.valueBytes[0];
  const rawTextBytes = item.valueBytes.slice(1);
  const text = new TextDecoder("latin1").decode(Uint8Array.from(rawTextBytes));
  return {
    fields: [
      field("Text string TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("Data coding scheme", `0x${dcs.toString(16).toUpperCase().padStart(2, "0")}`),
      field("Decoded text", text || "(empty)", { certainty: "possible" }),
    ],
  };
}

function decodeItem(item) {
  return {
    fields: [
      field("Item TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("Item identifier", item.valueBytes.length ? item.valueBytes[0] : "Not present"),
      field("Item text", item.valueBytes.length > 1 ? new TextDecoder("latin1").decode(Uint8Array.from(item.valueBytes.slice(1))) : "None", {
        certainty: "possible",
      }),
    ],
  };
}

function decodeFileList(item) {
  const files = [];
  for (let offset = 0; offset + 1 < item.valueBytes.length; offset += 2) {
    files.push(`${item.valueBytes[offset].toString(16).toUpperCase().padStart(2, "0")}${item.valueBytes[offset + 1].toString(16).toUpperCase().padStart(2, "0")}`);
  }
  return {
    fields: [
      field("File list TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("Referenced file IDs", files.join(", ") || "None", { certainty: "possible" }),
    ],
  };
}

function decodeChannelData(item) {
  return {
    fields: [
      field("Channel data TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("Channel data", item.valueHex || "empty", { certainty: "possible" }),
    ],
  };
}

function decodeBearerDescription(item) {
  return {
    fields: [
      field("Bearer description TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("Bearer type", item.valueBytes.length ? `0x${item.valueBytes[0].toString(16).toUpperCase().padStart(2, "0")}` : "Not present", {
        certainty: "possible",
      }),
      field("Bearer parameters", item.valueBytes.slice(1).map((byte) => byte.toString(16).toUpperCase().padStart(2, "0")).join(" ") || "None", {
        certainty: "possible",
      }),
    ],
  };
}

function decodeCatItem(item) {
  switch (item.tagNumber) {
    case 0x01:
      return decodeCommandDetails(item);
    case 0x02:
      return decodeDeviceIdentities(item);
    case 0x03:
      return decodeResult(item);
    case 0x04:
      return decodeDuration(item);
    case 0x05:
      return decodeAlphaIdentifier(item);
    case 0x06:
      return decodeAddress(item);
    case 0x0d:
      return decodeTextString(item);
    case 0x0f:
      return decodeItem(item);
    case 0x12:
      return decodeFileList(item);
    case 0x32:
      return decodeBearerDescription(item);
    case 0x36:
      return decodeChannelData(item);
    default:
      return {
        fields: [
          field(catTagNames[item.tagNumber] || `Tag 0x${item.tagHex}`, `${item.valueHex || "empty"} (${item.length} byte(s))`, {
            certainty: catTagNames[item.tagNumber] ? "confirmed" : "possible",
          }),
        ],
      };
  }
}

export function decodeCatTlvPayload(bytes, contextTitle) {
  const tlv = parseCatTlv(bytes);
  const sections = [];
  const tlvFields = [];
  const warnings = [...tlv.warnings.map((message) => warning(message))];
  const summary = {};

  for (const item of tlv.items) {
    const tagName = catTagNames[item.tagNumber] || `Tag 0x${item.tagHex}`;
    if (![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0d, 0x0f, 0x12, 0x32, 0x36].includes(item.tagNumber)) {
      tlvFields.push(
        field(`${tagName}`, `${item.valueHex || "empty"} (${item.length} byte(s))`, {
          certainty: catTagNames[item.tagNumber] ? "confirmed" : "possible",
        }),
      );
    }
    const decoded = decodeCatItem(item);
    tlvFields.push(...(decoded.fields || []));
    if (decoded.summary) {
      Object.assign(summary, decoded.summary);
    }
    for (const currentWarning of decoded.warnings || []) {
      warnings.push(warning(currentWarning));
    }
  }

  sections.push(
    section(contextTitle, [
      field("Payload length", bytes.length),
      field("Decoded TLVs", tlv.items.length),
      field("Proactive command hint", summary.proactiveCommandType || "Not visible", {
        certainty: summary.proactiveCommandType ? "confirmed" : "possible",
      }),
    ]),
  );
  sections.push(section("CAT / USAT TLVs", tlvFields.length ? tlvFields : [field("TLVs", "No TLV items decoded", { certainty: "possible" })]));

  return { sections, warnings, summary, tlv };
}

export function decodeCatPayload(apdu, contextTitle) {
  const decoded = decodeCatTlvPayload(apdu.data.bytes, contextTitle);
  decoded.sections[0].fields.splice(1, 0, field("Payload bytes", apdu.data.spacedHex || "None"));
  addCommonApduSection(apdu, decoded.sections);
  return {
    sections: decoded.sections,
    warnings: decoded.warnings,
    decodedFields: {
      payloadLength: apdu.lc ?? 0,
      proactiveCommandType: decoded.summary.proactiveCommandType || "Not directly visible",
      ...decoded.summary,
    },
  };
}

export function decodeProactiveCommandTemplate(bytes) {
  const ber = parseBerTlv(bytes);
  const warnings = [...ber.warnings.map((message) => warning(message))];
  const outer = ber.items[0];
  if (!outer || outer.tagHex !== "D0") {
    return null;
  }

  const inner = decodeCatTlvPayload(outer.valueBytes, "Proactive command payload");
  warnings.push(...inner.warnings);

  const sections = [
    section("Proactive command template", [
      field("Template tag", `D0 (${outer.length} byte(s))`),
      field("Template class", outer.tagClass),
      field("Payload bytes", outer.valueHex || "None"),
      field("Proactive command type", inner.summary.proactiveCommandType || "Not visible", {
        certainty: inner.summary.proactiveCommandType ? "confirmed" : "possible",
      }),
    ]),
    ...inner.sections.slice(1),
  ];

  return {
    sections,
    warnings,
    decodedFields: {
      templateTag: "D0",
      proactiveCommandType: inner.summary.proactiveCommandType || "Not directly visible",
      ...inner.summary,
    },
    ber,
  };
}
