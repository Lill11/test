import { parseBerTlv, parseCatTlv } from "../../core/tlv.js";
import { field, section, warning } from "../../core/format.js";
import { addCommonApduSection } from "../shared.js";
import { getBaselineLabel } from "../../standards-baseline.js";

// Source baseline: ETSI TS 102 223 Release 17 proactive command tables, project-pinned
// to the V17.3.0 baseline. Entries are added only when confirmed by the standards/Wireshark.
const proactiveCommandCatalog = {
  0x01: { name: "REFRESH" },
  0x02: { name: "MORE TIME" },
  0x03: { name: "POLL INTERVAL" },
  0x04: { name: "POLLING OFF" },
  0x05: { name: "SET UP EVENT LIST" },
  0x10: { name: "SET UP CALL" },
  0x11: { name: "SEND SS" },
  0x12: { name: "SEND USSD" },
  0x13: { name: "SEND SHORT MESSAGE" },
  0x14: { name: "SEND DTMF" },
  0x15: { name: "LAUNCH BROWSER" },
  0x20: { name: "PLAY TONE" },
  0x21: { name: "DISPLAY TEXT" },
  0x22: { name: "GET INKEY" },
  0x23: { name: "GET INPUT" },
  0x24: { name: "SELECT ITEM" },
  0x25: { name: "SET UP MENU" },
  0x26: { name: "PROVIDE LOCAL INFORMATION" },
  0x27: { name: "TIMER MANAGEMENT" },
  0x28: { name: "SET UP IDLE MODE TEXT" },
  0x30: { name: "PERFORM CARD APDU" },
  0x31: { name: "POWER ON CARD" },
  0x32: { name: "POWER OFF CARD" },
  0x33: { name: "GET READER STATUS" },
  0x34: { name: "RUN AT COMMAND" },
  0x35: { name: "LANGUAGE NOTIFICATION" },
  0x40: { name: "OPEN CHANNEL" },
  0x41: { name: "CLOSE CHANNEL" },
  0x42: { name: "RECEIVE DATA" },
  0x43: { name: "SEND DATA" },
  0x44: { name: "GET CHANNEL STATUS" },
  0x45: { name: "SERVICE SEARCH" },
  0x46: { name: "GET SERVICE INFORMATION" },
  0x47: { name: "DECLARE SERVICE" },
  0x50: { name: "SET FRAMES" },
  0x51: { name: "GET FRAMES STATUS" },
  0x60: { name: "RETRIEVE MULTIMEDIA MESSAGE" },
  0x61: { name: "SUBMIT MULTIMEDIA MESSAGE" },
  0x62: { name: "DISPLAY MULTIMEDIA MESSAGE" },
  0x70: { name: "ACTIVATE" },
  0x71: { name: "CONTACTLESS STATE CHANGED" },
  0x72: { name: "COMMAND CONTAINER" },
  0x73: { name: "ENCAPSULATED SESSION CONTROL" },
  0x79: {
    name: "LSI Command / Manage LSI",
    supportedSince: "ETSI TS 102 223 V17.3.0 Release 17 baseline",
    note: "Release 17 CAT/eUICC LSI command family; older proactive-command tables may not contain 0x79.",
  },
};

export const proactiveCommandTypes = Object.fromEntries(
  Object.entries(proactiveCommandCatalog).map(([key, value]) => [Number(key), value.name]),
);

export const catTagNames = {
  0x01: "Command details",
  0x02: "Device identities",
  0x03: "Result",
  0x04: "Duration",
  0x05: "Alpha identifier",
  0x06: "Address",
  0x0a: "USSD string",
  0x0d: "Text string",
  0x0f: "Item",
  0x12: "File list",
  0x15: "Location information",
  0x17: "Default text",
  0x1e: "Icon identifier",
  0x1f: "Item icon identifier list",
  0x30: "Browser identity",
  0x31: "URL",
  0x32: "Bearer description",
  0x35: "Bearer independent protocol / buffer size",
  0x36: "Channel data",
  0x37: "Channel data length",
  0x39: "Buffer size",
  0x3a: "Card reader identifier / refresh policy",
  0x3b: "File update information",
  0x3c: "Channel status",
};

// Source: ETSI TS 102 223 / 3GPP TS 31.111 "Device identities" coding;
// aligned with Wireshark packet-etsi_card_app_toolkit.c device identity labels.
const deviceIdentities = {
  0x81: "UICC",
  0x82: "Terminal",
  0x83: "Network",
};

// Source: ETSI TS 102 223 "Duration" TLV coding.
const durationUnits = {
  0x00: "minutes",
  0x01: "seconds",
  0x02: "tenths of seconds",
};

// Source: ETSI TS 102 223 / 3GPP TS 31.111 "Result" TLV general result values;
// aligned with Wireshark packet-etsi_card_app_toolkit.c result code labels.
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
  0x23: "User cleared down call before connection or network release",
  0x24: "Action in contradiction with current timer state",
  0x25: "Interaction with call control by NAA temporarily busy",
  0x26: "Launch browser generic error",
  0x30: "Command beyond terminal capability",
  0x31: "Command type not understood by terminal",
  0x32: "Command data not understood by terminal",
  0x33: "Command number not known by terminal",
  0x34: "SS return error",
  0x35: "SMS RP-ERROR",
  0x36: "Error, required values are missing",
  0x37: "USSD return error",
  0x38: "Multiple card commands error",
  0x39: "Interaction with call control or MO-SM control permanent problem",
};

// Source references for proactive command qualifier semantics. Individual decoder tables
// below should stay within meanings explicitly confirmed by the cited standard or Wireshark.
const proactiveQualifierReferences = {
  0x01: "ETSI TS 102 223 clause 8.6 / 6.4.7 REFRESH",
  0x05: "ETSI TS 102 223 clause 8.6 / 6.4.8 SET UP EVENT LIST",
  0x10: "ETSI TS 102 223 clause 8.6 / 6.4.13 SET UP CALL",
  0x11: "ETSI TS 102 223 clause 8.6 / 3GPP TS 31.111 SEND SS",
  0x12: "ETSI TS 102 223 clause 8.6 / 3GPP TS 31.111 SEND USSD",
  0x13: "ETSI TS 102 223 clause 8.6 / 6.4.10 SEND SHORT MESSAGE",
  0x15: "ETSI TS 102 223 clause 8.6 / 6.4.26 LAUNCH BROWSER",
  0x20: "ETSI TS 102 223 clause 8.6 / 6.4.5 PLAY TONE",
  0x21: "ETSI TS 102 223 clause 8.6 / 6.4.1 DISPLAY TEXT",
  0x22: "ETSI TS 102 223 clause 8.6 / 6.4.2 GET INKEY",
  0x23: "ETSI TS 102 223 clause 8.6 / 6.4.3 GET INPUT",
  0x26: "ETSI TS 102 223 clause 8.6 / 6.4.15 PROVIDE LOCAL INFORMATION",
  0x27: "ETSI TS 102 223 clause 8.6 / 6.4.21 TIMER MANAGEMENT",
  0x34: "ETSI TS 102 223 proactive command table / Wireshark RUN AT COMMAND entry",
  0x35: "ETSI TS 102 223 proactive command table / Wireshark LANGUAGE NOTIFICATION entry",
  0x40: "ETSI TS 102 223 clause 8.6 / 6.4.27 OPEN CHANNEL",
  0x41: "ETSI TS 102 223 clause 8.6 / 6.4.28 CLOSE CHANNEL",
  0x42: "ETSI TS 102 223 clause 8.6 / 6.4.29 RECEIVE DATA",
  0x43: "ETSI TS 102 223 clause 8.6 / 6.4.30 SEND DATA",
  0x50: "ETSI TS 102 223 proactive command table / Wireshark SET FRAMES entry",
  0x51: "ETSI TS 102 223 proactive command table / Wireshark GET FRAMES STATUS entry",
  0x70: "ETSI TS 102 223 proactive command table / Wireshark ACTIVATE entry",
  0x71: "ETSI TS 102 223 proactive command table / Wireshark CONTACTLESS STATE CHANGED entry",
  0x72: "ETSI TS 102 223 proactive command table / Wireshark COMMAND CONTAINER entry",
  0x73: "ETSI TS 102 223 proactive command table / Wireshark ENCAPSULATED SESSION CONTROL entry",
  0x79: "ETSI TS 102 223 V17.3.0 Release 17 LSI COMMAND / Manage LSI baseline",
};

function formatQualifierHex(value) {
  return `0x${value.toString(16).toUpperCase().padStart(2, "0")}`;
}

function formatCommandTypeHex(value) {
  return `0x${value.toString(16).toUpperCase().padStart(2, "0")}`;
}

function formatProactiveCommandTypeDisplay(typeOfCommand, commandName) {
  return `${formatCommandTypeHex(typeOfCommand)} — ${commandName}`;
}

function warnReservedBits(value, allowedMask, label = "Reserved qualifier bits are set.") {
  return value & ~allowedMask ? [label] : [];
}

function bitState(value, bitNumber) {
  return ((value >> (bitNumber - 1)) & 0x01) === 1;
}

function decodeRefreshQualifier(qualifier) {
  // Source: ETSI TS 102 223 command-details coding for REFRESH; aligned with
  // Wireshark packet-etsi_card_app_toolkit.c refresh qualifier value_string table.
  const refreshModes = {
    0x00: {
      meaning: "NAA Initialization and Full File Change Notification",
      category: "NAA initialization with complete file change handling",
    },
    0x01: {
      meaning: "File Change Notification",
      category: "Targeted file update notification",
    },
    0x02: {
      meaning: "NAA Initialization and File Change Notification",
      category: "NAA re-initialization with selected file update notification",
    },
    0x03: {
      meaning: "NAA Initialization",
      category: "NAA initialization reset",
    },
    0x04: {
      meaning: "UICC Reset",
      category: "SIM/USIM initialization reset",
    },
    0x05: {
      meaning: "NAA Application Reset",
      category: "Application-level reset without full card reset",
    },
    0x06: {
      meaning: "NAA Session Reset",
      category: "Current application session reset",
    },
    0x07: {
      meaning: "Steering of Roaming",
      category: "Roaming-policy refresh mode",
    },
    0x08: {
      meaning: "Steering of Roaming for I-WLAN",
      category: "Roaming-policy refresh mode for I-WLAN",
    },
    0x09: {
      meaning: "eUICC Profile State Change",
      category: "eUICC profile state change / profile lifecycle notification",
    },
    0x0A: {
      meaning: "Application Update",
      category: "Application update notification",
    },
  };

  const matched = refreshModes[qualifier];
  return {
    meaning: matched ? matched.meaning : `Reserved / unsupported REFRESH mode ${formatQualifierHex(qualifier)}`,
    category: matched ? matched.category : "Reserved REFRESH qualifier value",
    fields: [],
    warnings: matched ? [] : [`REFRESH qualifier ${formatQualifierHex(qualifier)} is reserved or not yet mapped.`],
  };
}

function decodeOpenChannelQualifier(qualifier) {
  const immediate = bitState(qualifier, 1);
  const autoReconnect = bitState(qualifier, 2);
  const backgroundMode = bitState(qualifier, 3);
  const dnsRequested = bitState(qualifier, 4);
  return {
    meaning: backgroundMode
      ? "Immediate link establishment in background mode"
      : immediate
        ? "Immediate link establishment"
        : "On-demand link establishment",
    category: backgroundMode ? "BIP channel setup in background mode" : "BIP channel setup",
    fields: [
      field("Automatic reconnection", autoReconnect ? "requested" : "not requested", { certainty: "confirmed" }),
      field("Background mode", backgroundMode ? "requested" : "not requested", { certainty: "confirmed" }),
      field("DNS server address request", dnsRequested ? "requested" : "not requested", {
        certainty: dnsRequested ? "possible" : "confirmed",
        note: "Defined for packet data service bearer variants.",
      }),
    ],
    warnings: warnReservedBits(qualifier, 0x0f, "OPEN CHANNEL qualifier has RFU bits 5-8 set."),
  };
}

function decodeCloseChannelQualifier(qualifier) {
  return {
    meaning: qualifier === 0x00 ? "No extra qualifier semantics in the common CLOSE CHANNEL case" : "Mode-specific CLOSE CHANNEL qualifier",
    category: qualifier === 0x00 ? "Close channel" : "Close channel with bearer- or server-mode semantics",
    fields: [
      field("CLOSE CHANNEL common meaning", qualifier === 0x00 ? "No extra indication" : "Non-zero qualifier seen; this can indicate packet-data reuse or UICC Server Mode behavior in newer releases.", {
        certainty: qualifier === 0x00 ? "confirmed" : "possible",
      }),
      field("Packet-data reuse hint", bitState(qualifier, 1) ? "next CAT command may reopen with same bearer parameters" : "not indicated", {
        certainty: qualifier === 0x00 || qualifier === 0x01 ? "possible" : "possible",
      }),
      field("UICC Server Mode hint", bitState(qualifier, 1) ? "possible request to return TCP listener to LISTEN state" : "possible request to close TCP listener", {
        certainty: "possible",
        note: "The same bit is interpreted differently depending on bearer / server-mode context.",
      }),
    ],
    warnings: warnReservedBits(qualifier, 0x01, "CLOSE CHANNEL qualifier has RFU bits 2-8 set."),
  };
}

function decodeSendDataQualifier(qualifier) {
  return {
    meaning: bitState(qualifier, 1) ? "Send data immediately" : "Store data in Tx buffer",
    category: "BIP transmit behavior",
    fields: [],
    warnings: warnReservedBits(qualifier, 0x01, "SEND DATA qualifier has RFU bits 2-8 set."),
  };
}

function decodeReceiveDataQualifier(qualifier) {
  return {
    meaning: qualifier === 0x00 ? "No qualifier semantics defined" : "Qualifier should normally be zero (RFU).",
    category: "Receive data request",
    fields: [],
    warnings: qualifier === 0x00 ? [] : ["RECEIVE DATA qualifier is RFU and should normally be 0x00."],
  };
}

function decodeDisplayTextQualifier(qualifier) {
  const highPriority = bitState(qualifier, 1);
  const waitForClear = bitState(qualifier, 8);
  return {
    meaning: `${highPriority ? "High" : "Normal"} priority, ${waitForClear ? "wait for user to clear message" : "clear after a delay"}`,
    category: highPriority ? "Urgent display behavior" : "Standard display behavior",
    fields: [
      field("Display priority", highPriority ? "high priority" : "normal priority", { certainty: "confirmed" }),
      field("User-clear behavior", waitForClear ? "wait for user to clear message" : "clear message after a delay", { certainty: "confirmed" }),
    ],
    warnings: warnReservedBits(qualifier, 0x81, "DISPLAY TEXT qualifier has RFU bits 2-7 set."),
  };
}

function decodeGetInkeyQualifier(qualifier) {
  const alphabetSet = bitState(qualifier, 1);
  const ucs2 = bitState(qualifier, 2);
  const yesNo = bitState(qualifier, 3);
  const immediateDigit = bitState(qualifier, 4);
  const help = bitState(qualifier, 8);
  return {
    meaning: yesNo
      ? `${immediateDigit ? "Immediate" : "User-confirmed"} Yes/No response, ${help ? "help available" : "no help information"}`
      : `${alphabetSet ? "Alphabet" : "Digits-only"} input, ${ucs2 ? "UCS2 alphabet" : "SMS default alphabet"}, ${immediateDigit ? "immediate digit response requested" : "user response displayed"}, ${help ? "help available" : "no help information"}`,
    category: yesNo ? "Binary user confirmation request" : "Single-key input request",
    fields: [
      field("Allowed character family", yesNo ? "Disabled because Yes/No response is requested" : alphabetSet ? "alphabet set" : "digits only", {
        certainty: "confirmed",
      }),
      field("Alphabet coding", yesNo ? "Not applicable in Yes/No mode" : ucs2 ? "UCS2 alphabet" : "SMS default alphabet", { certainty: "confirmed" }),
      field("Response mode", yesNo ? "Yes/No response requested" : immediateDigit ? "Immediate digit response requested" : "User response shall be displayed", {
        certainty: "confirmed",
      }),
      field("Help information", help ? "available" : "not available", { certainty: "confirmed" }),
    ],
    warnings: warnReservedBits(qualifier, 0x8f, "GET INKEY qualifier has RFU bits 5-7 set."),
  };
}

function decodeGetInputQualifier(qualifier) {
  const alphabetSet = bitState(qualifier, 1);
  const ucs2 = bitState(qualifier, 2);
  const hidden = bitState(qualifier, 3);
  const packed = bitState(qualifier, 4);
  const help = bitState(qualifier, 8);
  return {
    meaning: `${alphabetSet ? "Alphabet" : "Digits-only"} input, ${ucs2 ? "UCS2 alphabet" : "SMS default alphabet"}, ${hidden ? "hidden entry" : "echo allowed"}, ${packed ? "SMS packed format" : "unpacked format"}, ${help ? "help available" : "no help information"}`,
    category: hidden ? "Protected user input" : "Visible user input",
    fields: [
      field("Allowed character family", alphabetSet ? "alphabet set" : "digits only", { certainty: "confirmed" }),
      field("Alphabet coding", ucs2 ? "UCS2 alphabet" : "SMS default alphabet", { certainty: "confirmed" }),
      field("Display echo behavior", hidden ? "user input shall not be revealed" : "terminal may echo user input", { certainty: "confirmed" }),
      field("Input packing", packed ? "SMS packed format" : "unpacked format", { certainty: "confirmed" }),
      field("Help information", help ? "available" : "not available", { certainty: "confirmed" }),
    ],
    warnings: warnReservedBits(qualifier, 0x8f, "GET INPUT qualifier has RFU bits 5-7 set."),
  };
}

function decodeSetUpEventListQualifier(qualifier) {
  return {
    meaning: qualifier === 0x00 ? "RFU byte correctly set to 0" : "Qualifier should normally be 0x00 (RFU).",
    category: "Event-list definition",
    fields: [
      field("SET UP EVENT LIST qualifier meaning", qualifier === 0x00 ? "No qualifier semantics defined" : "Non-zero qualifier in RFU field", {
        certainty: qualifier === 0x00 ? "confirmed" : "possible",
      }),
    ],
    warnings: qualifier === 0x00 ? [] : ["SET UP EVENT LIST qualifier is RFU and should normally be 0x00."],
  };
}

function decodeProvideLocalInformationQualifier(qualifier) {
  const modes = {
    0x00: "Location Information according to current NAA",
    0x01: "IMEI of the terminal",
    0x02: "Network Measurement results according to current NAA",
    0x03: "Date, time and time zone",
    0x04: "Language setting",
    0x05: "Reserved for GSM / legacy Timing Advance semantics",
    0x06: "Access Technology (single access technology)",
    0x07: "ESN of the terminal",
    0x08: "IMEISV of the terminal",
    0x09: "Search Mode",
    0x0A: "Charge State of the Battery",
    0x0B: "MEID of the terminal",
    0x0C: "Reserved for 3GPP / current WSID",
    0x0D: "Broadcast Network information",
    0x0E: "Multiple Access Technologies",
    0x0F: "Location Information for multiple access technologies",
    0x10: "Network Measurement results for multiple access technologies",
  };
  const meaning = modes[qualifier];
  return {
    meaning: meaning || `Reserved / unsupported PROVIDE LOCAL INFORMATION mode ${formatQualifierHex(qualifier)}`,
    category: meaning ? "Terminal information request" : "Reserved PLI qualifier value",
    fields: [],
    warnings: meaning ? [] : [`PROVIDE LOCAL INFORMATION qualifier ${formatQualifierHex(qualifier)} is reserved or not yet mapped.`],
  };
}

function decodeTimerManagementQualifier(qualifier) {
  const action = qualifier & 0x03;
  const actions = {
    0x00: "Start timer",
    0x01: "Deactivate timer",
    0x02: "Get current timer value",
    0x03: "RFU",
  };
  return {
    meaning: actions[action],
    category: "Timer control",
    fields: [
      field("Timer action", actions[action], {
        certainty: action === 0x03 ? "possible" : "confirmed",
      }),
    ],
    warnings: [
      ...(action === 0x03 ? ["TIMER MANAGEMENT qualifier uses RFU action value 0b11."] : []),
      ...warnReservedBits(qualifier, 0x03, "TIMER MANAGEMENT qualifier has RFU bits 3-8 set."),
    ],
  };
}

function decodePlayToneQualifier(qualifier) {
  return {
    meaning: bitState(qualifier, 1) ? "Vibrate alert with the tone, if available" : "Vibrate alert use is up to the terminal",
    category: "Tone playback behavior",
    fields: [],
    warnings: warnReservedBits(qualifier, 0x01, "PLAY TONE qualifier has RFU bits 2-8 set."),
  };
}

function decodeLaunchBrowserQualifier(qualifier) {
  const modes = {
    0x00: "Launch browser if not already launched",
    0x02: "Use the existing browser session (without using the active secured session)",
    0x03: "Close the existing browser session and launch a new browser session",
  };
  return {
    meaning: modes[qualifier] || `Reserved / not used LAUNCH BROWSER mode ${formatQualifierHex(qualifier)}`,
    category: "Browser launch policy",
    fields: [],
    warnings: modes[qualifier] ? [] : [`LAUNCH BROWSER qualifier ${formatQualifierHex(qualifier)} is reserved or marked as not used.`],
  };
}

function decodeSetUpCallQualifier(qualifier) {
  const modes = {
    0x00: "Set up call only if not currently busy on another call",
    0x01: "Set up call only if not currently busy on another call, with redial",
    0x02: "Set up call, putting all other calls on hold",
    0x03: "Set up call, putting all other calls on hold, with redial",
    0x04: "Set up call, disconnecting all other calls",
    0x05: "Set up call, disconnecting all other calls, with redial",
  };
  return {
    meaning: modes[qualifier] || `Reserved / unsupported SET UP CALL mode ${formatQualifierHex(qualifier)}`,
    category: "Call setup policy",
    fields: [],
    warnings: modes[qualifier] ? [] : [`SET UP CALL qualifier ${formatQualifierHex(qualifier)} is reserved.`],
  };
}

function decodeSendShortMessageQualifier(qualifier) {
  return {
    meaning: bitState(qualifier, 1) ? "SMS packing by the terminal required" : "Packing not required",
    category: "SMS payload handling",
    fields: [],
    warnings: warnReservedBits(qualifier, 0x01, "SEND SHORT MESSAGE qualifier has RFU bits 2-8 set."),
  };
}

function decodeRfuQualifier(commandName, qualifier) {
  return {
    meaning: qualifier === 0x00 ? "No qualifier semantics defined" : `${commandName} qualifier should normally be 0x00 (RFU).`,
    category: "Qualifier not used by this command",
    fields: [],
    warnings: qualifier === 0x00 ? [] : [`${commandName} qualifier is RFU and should normally be 0x00.`],
  };
}

function decodeLsiCommandQualifier(qualifier) {
  return {
    meaning: "unknown / not decoded yet",
    category: "LSI command qualifier semantics not yet confirmed",
    fields: [],
    warnings: qualifier === 0x00 ? [] : [`LSI Command qualifier ${formatQualifierHex(qualifier)} is recognized structurally but not yet semantically decoded.`],
  };
}

function decodeProactiveCommandQualifier(typeOfCommand, qualifier) {
  switch (typeOfCommand) {
    case 0x01:
      return decodeRefreshQualifier(qualifier);
    case 0x05:
      return decodeSetUpEventListQualifier(qualifier);
    case 0x10:
      return decodeSetUpCallQualifier(qualifier);
    case 0x11:
      return decodeRfuQualifier("SEND SS", qualifier);
    case 0x12:
      return decodeRfuQualifier("SEND USSD", qualifier);
    case 0x13:
      return decodeSendShortMessageQualifier(qualifier);
    case 0x15:
      return decodeLaunchBrowserQualifier(qualifier);
    case 0x20:
      return decodePlayToneQualifier(qualifier);
    case 0x21:
      return decodeDisplayTextQualifier(qualifier);
    case 0x22:
      return decodeGetInkeyQualifier(qualifier);
    case 0x23:
      return decodeGetInputQualifier(qualifier);
    case 0x26:
      return decodeProvideLocalInformationQualifier(qualifier);
    case 0x27:
      return decodeTimerManagementQualifier(qualifier);
    case 0x40:
      return decodeOpenChannelQualifier(qualifier);
    case 0x41:
      return decodeCloseChannelQualifier(qualifier);
    case 0x42:
      return decodeReceiveDataQualifier(qualifier);
    case 0x43:
      return decodeSendDataQualifier(qualifier);
    case 0x79:
      return decodeLsiCommandQualifier(qualifier);
    default:
      return {
        meaning: "unknown / command-type-specific qualifier semantics unavailable",
        category: "Qualifier semantics unavailable for this command type in the loaded CAT table",
        fields: [],
        warnings: [],
      };
  }
}

function decodeCommandDetails(item) {
  if (item.valueBytes.length < 3) {
    return { fields: [field("Command details", "TLV too short", { certainty: "possible" })], warnings: ["Command details TLV is shorter than 3 bytes."], summary: {} };
  }

  const [commandNumber, typeOfCommand, commandQualifier] = item.valueBytes;
  const commandEntry = proactiveCommandCatalog[typeOfCommand] || null;
  const proactiveCommandTypeName = commandEntry?.name || formatCommandTypeHex(typeOfCommand);
  const proactiveCommandTypeDisplay = formatProactiveCommandTypeDisplay(typeOfCommand, proactiveCommandTypeName);
  const qualifierDecode = decodeProactiveCommandQualifier(typeOfCommand, commandQualifier);
  const qualifierReference = proactiveQualifierReferences[typeOfCommand] || "ETSI TS 102 223 clause 8.6 command qualifier coding";
  const commandTypeStatus = commandEntry
    ? null
    : `Command type ${formatCommandTypeHex(typeOfCommand)} is not present in the currently loaded standard table. Please verify ETSI TS 102 223 version coverage.`;
  return {
    fields: [
      field("Command details TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("Command details value", `${item.valueHex} (${item.length} byte(s))`),
      field("Command number", commandNumber),
      field("Proactive command type", proactiveCommandTypeDisplay, {
        certainty: commandEntry ? "confirmed" : "possible",
      }),
      field("Command qualifier", formatQualifierHex(commandQualifier)),
      field("Command qualifier meaning", qualifierDecode.meaning, {
        certainty:
          qualifierDecode.meaning === "unknown / not decoded yet" ||
          qualifierDecode.meaning === "unknown / command-type-specific qualifier semantics unavailable" ||
          qualifierDecode.meaning.startsWith("Reserved")
            ? "possible"
            : "confirmed",
      }),
      ...(commandTypeStatus
        ? [
            field("Command type status", commandTypeStatus, {
              certainty: "possible",
            }),
          ]
        : []),
      field("Standard table", getBaselineLabel("etsi102223Cat"), {
        certainty: "confirmed",
      }),
      field("Standard reference", qualifierReference, {
        certainty: "possible",
      }),
      ...qualifierDecode.fields,
    ],
    warnings: qualifierDecode.warnings,
    summary: {
      commandNumber,
      proactiveCommandType: proactiveCommandTypeDisplay,
      proactiveCommandTypeName,
      proactiveCommandTypeByte: formatCommandTypeHex(typeOfCommand),
      commandQualifier,
      commandQualifierMeaning: qualifierDecode.meaning,
      commandQualifierReference: qualifierReference,
      proactiveCommandTableVersion: getBaselineLabel("etsi102223Cat"),
      commandTypeStatus: commandTypeStatus || "recognized in loaded CAT table",
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
      field("General result code", `0x${generalResult.toString(16).toUpperCase().padStart(2, "0")}`),
      field("Meaning", resultMeaning, {
        certainty: resultMeanings[generalResult] ? "confirmed" : "possible",
      }),
      field("Additional info bytes", item.valueBytes.length > 1 ? item.valueHex.slice(2) : "None", {
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

function decodeUssdString(item) {
  return {
    fields: [
      field("USSD string TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("Data coding scheme", item.valueBytes.length ? `0x${item.valueBytes[0].toString(16).toUpperCase().padStart(2, "0")}` : "Not present"),
      field("USSD payload", item.valueBytes.slice(1).map((byte) => byte.toString(16).toUpperCase().padStart(2, "0")).join(" ") || "None", {
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

function decodeDefaultText(item) {
  const text = new TextDecoder("latin1").decode(Uint8Array.from(item.valueBytes));
  return {
    fields: [
      field("Default text TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("Default text", text || "(empty)", { certainty: "possible" }),
    ],
  };
}

function decodeIconIdentifier(item) {
  return {
    fields: [
      field("Icon identifier TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("Icon qualifier", item.valueBytes.length ? `0x${item.valueBytes[0].toString(16).toUpperCase().padStart(2, "0")}` : "Not present", {
        certainty: "possible",
      }),
      field("Icon identifier", item.valueBytes.length > 1 ? item.valueBytes[1] : "Not present"),
    ],
  };
}

function decodeBrowserIdentity(item) {
  return {
    fields: [
      field("Browser identity TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("Browser identity", item.valueHex || "empty", { certainty: "possible" }),
    ],
  };
}

function decodeUrl(item) {
  const text = new TextDecoder("latin1").decode(Uint8Array.from(item.valueBytes));
  return {
    fields: [
      field("URL TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("URL text", text || "(empty)", { certainty: "possible" }),
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

function decodeBufferSize(item) {
  const size = item.valueBytes.length >= 2 ? (item.valueBytes[0] << 8) | item.valueBytes[1] : null;
  return {
    fields: [
      field("Buffer size TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("Buffer size", size === null ? "Not present" : `${size} byte(s)`, {
        certainty: size === null ? "possible" : "confirmed",
      }),
    ],
  };
}

function decodeFileUpdateInformation(item) {
  return {
    fields: [
      field("File update information TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("File update payload", item.valueHex || "empty", { certainty: "possible" }),
    ],
  };
}

function decodeChannelStatus(item) {
  return {
    fields: [
      field("Channel status TLV", `${item.tlvSpacedHex} (${item.tlvBytes.length} byte(s))`),
      field("Channel status value", item.valueHex || "empty", { certainty: "possible" }),
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
    case 0x0a:
      return decodeUssdString(item);
    case 0x0d:
      return decodeTextString(item);
    case 0x0f:
      return decodeItem(item);
    case 0x17:
      return decodeDefaultText(item);
    case 0x1e:
      return decodeIconIdentifier(item);
    case 0x30:
      return decodeBrowserIdentity(item);
    case 0x31:
      return decodeUrl(item);
    case 0x12:
      return decodeFileList(item);
    case 0x32:
      return decodeBearerDescription(item);
    case 0x36:
      return decodeChannelData(item);
    case 0x39:
      return decodeBufferSize(item);
    case 0x3b:
      return decodeFileUpdateInformation(item);
    case 0x3c:
      return decodeChannelStatus(item);
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
    if (![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0a, 0x0d, 0x0f, 0x12, 0x17, 0x1e, 0x30, 0x31, 0x32, 0x36, 0x39, 0x3b, 0x3c].includes(item.tagNumber)) {
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
