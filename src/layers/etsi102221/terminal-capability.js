import { field, section, warning } from "../../core/format.js";
import { parseBerTlv } from "../../core/tlv.js";
import { addCommonApduSection } from "../shared.js";

const supplyVoltageClasses = [
  { mask: 0x01, name: "Class A (5 V)" },
  { mask: 0x02, name: "Class B (3 V)" },
  { mask: 0x04, name: "Class C (1.8 V)" },
];

const additionalInterfaceFlags = [
  { mask: 0x01, name: "UICC-CLF interface supported" },
];

const euiccCapabilityFlags = [
  { mask: 0x01, name: "Local profile management supported" },
  { mask: 0x02, name: "Profile download supported" },
];

function decodeFlags(byte, definitions) {
  return definitions.filter((entry) => (byte & entry.mask) !== 0).map((entry) => entry.name);
}

function decodeVoltageClass(byte) {
  const flags = decodeFlags(byte, supplyVoltageClasses);
  return flags.length ? flags.join(", ") : `0x${byte.toString(16).toUpperCase().padStart(2, "0")} (RFU/unknown)`;
}

function decodeTerminalPowerSupply(item) {
  if (item.valueBytes.length < 3) {
    return {
      fields: [field("Terminal power supply TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`)],
      warnings: ["Terminal power supply TLV should contain 3 value byte(s)."],
    };
  }

  const voltageClass = decodeVoltageClass(item.valueBytes[0]);
  const maxPowerMa = item.valueBytes[1];
  const clockByte = item.valueBytes[2];
  const clockMeaning = clockByte === 0xff ? "No clock frequency indicated" : `${(clockByte / 10).toFixed(1)} MHz`;

  return {
    fields: [
      field("Terminal power supply TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("Supply voltage class", voltageClass, { certainty: "confirmed" }),
      field("Maximum available power", `${maxPowerMa} mA`),
      field("Clock frequency", clockMeaning, { certainty: clockByte === 0xff ? "possible" : "confirmed" }),
    ],
    summary: {
      terminalVoltageClass: voltageClass,
      terminalMaxPower: `${maxPowerMa} mA`,
      terminalClockFrequency: clockMeaning,
    },
  };
}

function decodeExtendedLogicalChannels(item) {
  return {
    fields: [
      field("Extended logical channels TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("Meaning", item.length === 0 ? "Extended logical channel support indicated" : "Extended logical channel support indicated with future-extension bytes", {
        certainty: "confirmed",
      }),
    ],
    summary: {
      extendedLogicalChannelsSupport: "Indicated",
    },
  };
}

function decodeAdditionalInterfaces(item) {
  if (item.valueBytes.length < 1) {
    return {
      fields: [field("Additional interfaces TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`)],
      warnings: ["Additional interfaces support TLV should contain at least 1 value byte."],
    };
  }

  const supported = decodeFlags(item.valueBytes[0], additionalInterfaceFlags);
  return {
    fields: [
      field("Additional interfaces TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("Additional interface bits", `0x${item.valueBytes[0].toString(16).toUpperCase().padStart(2, "0")}`),
      field("Recognized interfaces", supported.join(", ") || "No mapped additional interfaces set", {
        certainty: supported.length ? "confirmed" : "possible",
      }),
    ],
    summary: {
      additionalInterfaces: supported.join(", ") || "No mapped additional interfaces set",
    },
  };
}

function decodeEuiccCapabilities(item) {
  if (item.valueBytes.length < 1) {
    return {
      fields: [field("eUICC-related capabilities TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`)],
      warnings: ["eUICC-related capabilities TLV should contain at least 1 value byte."],
    };
  }

  const supported = decodeFlags(item.valueBytes[0], euiccCapabilityFlags);
  return {
    fields: [
      field("eUICC-related capabilities TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("Capability bits", `0x${item.valueBytes[0].toString(16).toUpperCase().padStart(2, "0")}`),
      field("Recognized capabilities", supported.join(", ") || "No mapped eUICC capabilities set", {
        certainty: supported.length ? "confirmed" : "possible",
      }),
      ...(item.valueBytes.length > 1
        ? [field("Additional capability bytes", item.valueHex.slice(2), {
            certainty: "possible",
            note: "Later GSMA eUICC profiles may append private or version-specific capability bytes.",
          })]
        : []),
    ],
    summary: {
      euiccCapabilities: supported.join(", ") || "No mapped eUICC capabilities set",
    },
  };
}

function decodeTerminalCapabilityTemplate(dataBytes) {
  const ber = parseBerTlv(dataBytes);
  const warnings = [...ber.warnings.map((message) => warning(message))];
  const outer = ber.items[0];
  if (!outer || outer.tagHex !== "A9") {
    return {
      sections: [
        section("Terminal capability payload", [
          field("Payload bytes", dataBytes.map((byte) => byte.toString(16).toUpperCase().padStart(2, "0")).join(" ")),
          field("Template recognition", "Expected constructed terminal capability template tag A9 was not found", {
            certainty: "possible",
          }),
        ]),
      ],
      decodedFields: {
        terminalCapabilityTemplate: "Not recognized",
      },
      warnings: [...warnings, warning("TERMINAL CAPABILITY payload does not begin with the expected A9 constructed template.", "warning")],
    };
  }

  const inner = parseBerTlv(outer.valueBytes);
  warnings.push(...inner.warnings.map((message) => warning(message)));
  const fields = [
    field("Terminal capability template", `${outer.tlvSpacedHex} (${outer.tlvBytes.length} byte(s))`),
    field("Template payload length", outer.length),
  ];
  const summary = {};

  for (const item of inner.items) {
    let decoded;
    switch (item.tagHex) {
      case "80":
        decoded = decodeTerminalPowerSupply(item);
        break;
      case "81":
        decoded = decodeExtendedLogicalChannels(item);
        break;
      case "82":
        decoded = decodeAdditionalInterfaces(item);
        break;
      case "83":
        decoded = decodeEuiccCapabilities(item);
        break;
      default:
        decoded = {
          fields: [
            field(`Private / RFU TLV 0x${item.tagHex}`, `${item.valueHex || "empty"} (${item.length} byte(s))`, {
              certainty: "possible",
            }),
          ],
        };
        warnings.push(warning(`TERMINAL CAPABILITY contains unsupported inner TLV tag 0x${item.tagHex}; preserved as raw TLV.`, "info"));
        break;
    }
    fields.push(...(decoded.fields || []));
    Object.assign(summary, decoded.summary || {});
    for (const currentWarning of decoded.warnings || []) {
      warnings.push(warning(currentWarning));
    }
  }

  return {
    sections: [section("Terminal capability payload", fields)],
    decodedFields: {
      terminalCapabilityTemplate: "A9",
      ...summary,
    },
    warnings,
  };
}

export function decodeTerminalCapabilityCommand(apdu) {
  const decoded = decodeTerminalCapabilityTemplate(apdu.data.bytes);
  addCommonApduSection(apdu, decoded.sections);
  return decoded;
}
