import { parseBerTlv } from "../../core/tlv.js";
import { toHex } from "../../core/hex.js";
import { field, section, warning } from "../../core/format.js";
import { addCommonApduSection, classMatches } from "../shared.js";

function decodeSelect(apdu) {
  const modeMap = {
    0x00: "Select MF/DF/EF by file identifier",
    0x01: "Select child DF of current DF",
    0x02: "Select EF under current DF",
    0x03: "Select parent DF",
    0x04: "Select by DF name / AID",
    0x08: "Select path from MF",
    0x09: "Select path from current DF",
  };
  const responseMap = {
    0x00: "Return FCI/FCP according to card policy",
    0x04: "Return FCP template",
    0x08: "Return FMD template",
    0x0c: "No response data requested",
  };
  const selectionReference =
    apdu.p1 === 0x04
      ? apdu.data.hex
        ? `AID ${apdu.data.hex}`
        : "AID expected but missing"
      : apdu.data.hex
        ? `Identifier/path ${apdu.data.hex}`
        : "Current selection context";

  const sections = [
    section("Selection decoding", [
      field("Selection mode", modeMap[apdu.p1] || `Mode 0x${apdu.p1Hex}`, { certainty: modeMap[apdu.p1] ? "confirmed" : "possible" }),
      field("Selection reference", selectionReference),
      field("Response control", responseMap[apdu.p2] || `P2=0x${apdu.p2Hex}`),
      field("Le meaning", apdu.le === null ? "No Le: selection response depends on card behavior." : `Expect up to ${apdu.le} byte(s) of selection response`),
    ]),
  ];
  addCommonApduSection(apdu, sections);
  return { sections, decodedFields: {
    selectionMode: modeMap[apdu.p1] || `Mode 0x${apdu.p1Hex}`,
    selectionReference,
    responseControl: responseMap[apdu.p2] || `P2=0x${apdu.p2Hex}`,
  } };
}

function decodeStatus(apdu) {
  const sections = [
    section("Status decoding", [
      field("Qualifier", `P1=0x${apdu.p1Hex}`),
      field("Response control", `P2=0x${apdu.p2Hex}`),
      field("Expected response", apdu.le === null ? "Not present" : `${apdu.le} byte(s)`),
    ]),
  ];
  addCommonApduSection(apdu, sections);
  return { sections, decodedFields: { expectedLength: apdu.le ?? "Not present" } };
}

function decodeReadBinary(apdu) {
  const sfiMode = (apdu.p1 & 0x80) !== 0;
  const offset = sfiMode ? apdu.p2 : ((apdu.p1 & 0x7f) << 8) | apdu.p2;
  const sections = [
    section("Binary access", [
      field("Addressing mode", sfiMode ? "Short File Identifier (SFI)" : "Absolute offset"),
      field("SFI", sfiMode ? `0x${toHex((apdu.p1 >> 3) & 0x1f)}` : "Not present"),
      field("Offset", offset),
      field("Expected length", apdu.le === null ? "Not present" : `${apdu.le} byte(s)`),
      field("File model", "Transparent EF interpretation"),
    ]),
  ];
  addCommonApduSection(apdu, sections);
  return { sections, decodedFields: { offset, requestedLength: apdu.le ?? "Not present" } };
}

function decodeUpdateBinary(apdu) {
  const sections = [
    section("Binary update", [
      field("Offset", ((apdu.p1 & 0x7f) << 8) | apdu.p2),
      field("Data length", apdu.lc ?? 0),
      field("Write payload", apdu.data.spacedHex || "None"),
    ]),
  ];
  addCommonApduSection(apdu, sections);
  return { sections, decodedFields: { offset: ((apdu.p1 & 0x7f) << 8) | apdu.p2, dataLength: apdu.lc ?? 0 } };
}

function decodeRecordAccess(apdu, modeText) {
  const recordMode = {
    0x02: "Next record",
    0x03: "Previous record",
    0x04: "Absolute record number",
  }[apdu.p2 & 0x07] || `Mode 0x${toHex(apdu.p2 & 0x07)}`;
  const sfi = apdu.p2 >> 3;

  const sections = [
    section(`${modeText} record`, [
      field("Record selector", apdu.p1),
      field("Mode", recordMode),
      field("SFI", sfi ? `0x${toHex(sfi)}` : "Current EF"),
      field(modeText === "Read" ? "Expected length" : "Data length", modeText === "Read" ? (apdu.le ?? "Not present") : (apdu.lc ?? 0)),
      field("Payload", modeText === "Read" ? "Command carries no data" : apdu.data.spacedHex || "None"),
    ]),
  ];
  addCommonApduSection(apdu, sections);
  return {
    sections,
    decodedFields: {
      recordNumber: apdu.p1,
      mode: recordMode,
      sfi: sfi ? `0x${toHex(sfi)}` : "Current EF",
    },
  };
}

function decodePin(apdu, operation) {
  const sections = [
    section(`${operation} decoding`, [
      field("Reference qualifier", `PIN/CHV reference 0x${apdu.p2Hex}`),
      field("Control qualifier", `P1=0x${apdu.p1Hex}`),
      field("PIN data length", apdu.lc ?? 0),
      field("PIN payload", apdu.data.spacedHex || "None", { certainty: "possible", note: "Payload bytes may be plaintext, padded, or transport-wrapped depending on the environment." }),
    ]),
  ];
  addCommonApduSection(apdu, sections);
  return { sections, decodedFields: { referenceDataQualifier: `PIN/CHV reference 0x${apdu.p2Hex}`, pinDataLength: apdu.lc ?? 0 } };
}

function decodeAuthenticate(apdu) {
  const sections = [
    section("Authentication context", [
      field("Qualifier", `P1=0x${apdu.p1Hex}`),
      field("Context", apdu.p2 === 0x80 ? "AKA/USIM-style challenge context" : `P2=0x${apdu.p2Hex}`, {
        certainty: apdu.p2 === 0x80 ? "confirmed" : "possible",
      }),
      field("Challenge length", apdu.lc ?? 0),
      field("Challenge / auth data", apdu.data.spacedHex || "None"),
    ]),
  ];
  addCommonApduSection(apdu, sections);
  return { sections, decodedFields: { challengeLength: apdu.lc ?? 0 } };
}

function decodeGetData(apdu) {
  const sections = [
    section("Data object access", [
      field("Reference / tag", `0x${apdu.p1Hex}${apdu.p2Hex}`),
      field("Expected length", apdu.le === null ? "Not present" : `${apdu.le} byte(s)`),
    ]),
  ];
  addCommonApduSection(apdu, sections);
  return { sections, decodedFields: { tagReference: `0x${apdu.p1Hex}${apdu.p2Hex}` } };
}

function decodePutData(apdu) {
  const tlv = parseBerTlv(apdu.data.bytes);
  const sections = [
    section("Data object update", [
      field("Reference / tag", `0x${apdu.p1Hex}${apdu.p2Hex}`),
      field("Payload length", apdu.lc ?? 0),
      field("Payload bytes", apdu.data.spacedHex || "None"),
      field("BER-TLV items", tlv.items.length),
    ]),
  ];
  addCommonApduSection(apdu, sections);
  return {
    sections,
    warnings: tlv.warnings.map((message) => warning(message)),
    decodedFields: { tagReference: `0x${apdu.p1Hex}${apdu.p2Hex}`, tlvItems: tlv.items.length },
  };
}

function decodeGetResponse(apdu) {
  const sections = [
    section("Response retrieval", [
      field("Expected response size", apdu.le === null ? "Not present" : `${apdu.le} byte(s)`),
      field("Usage", "Usually follows SW1=61 or similar response continuation semantics."),
    ]),
  ];
  addCommonApduSection(apdu, sections);
  return { sections, decodedFields: { expectedLength: apdu.le ?? "Not present" } };
}

function decodeFileAdministration(apdu, name) {
  const sections = [
    section(`${name} semantics`, [
      field("Qualifier", `P1=0x${apdu.p1Hex}`),
      field("Control", `P2=0x${apdu.p2Hex}`),
      field("Payload length", apdu.lc ?? 0),
      field("Payload bytes", apdu.data.spacedHex || "None"),
    ]),
  ];
  addCommonApduSection(apdu, sections);
  return { sections, decodedFields: { qualifier: `0x${apdu.p1Hex}`, control: `0x${apdu.p2Hex}` } };
}

function decodeManageChannel(apdu) {
  const sections = [
    section("Logical channel control", [
      field("Operation", apdu.p1 === 0x00 ? "Open channel" : apdu.p1 === 0x80 ? "Close channel" : `P1=0x${apdu.p1Hex}`),
      field("Target channel", apdu.p2 === 0x00 ? "Current / card-chosen channel" : apdu.p2),
      field("Expected length", apdu.le === null ? "Not present" : `${apdu.le} byte(s)`),
    ]),
  ];
  addCommonApduSection(apdu, sections);
  return { sections, decodedFields: { operation: apdu.p1 === 0x80 ? "Close logical channel" : "Open logical channel" } };
}

function decodeSearchRecord(apdu) {
  const sections = [
    section("Record search", [
      field("Start record", apdu.p1),
      field("Mode", (apdu.p2 & 0x07) === 0x04 ? "Forward search" : (apdu.p2 & 0x07) === 0x05 ? "Backward search" : `Mode 0x${toHex(apdu.p2 & 0x07)}`),
      field("Template / pattern length", apdu.lc ?? 0),
      field("Search payload", apdu.data.spacedHex || "None"),
    ]),
  ];
  addCommonApduSection(apdu, sections);
  return { sections, decodedFields: { searchTemplateLength: apdu.lc ?? 0 } };
}

function decodeIncrease(apdu) {
  const sections = [
    section("Value increment", [
      field("Amount length", apdu.lc ?? 0),
      field("Amount bytes", apdu.data.spacedHex || "None"),
      field("Expected response length", apdu.le === null ? "Not present" : `${apdu.le} byte(s)`),
    ]),
  ];
  addCommonApduSection(apdu, sections);
  return { sections, decodedFields: { amountLength: apdu.lc ?? 0 } };
}

export const ISO7816_COMMANDS = [
  {
    id: "iso.select",
    name: "SELECT FILE",
    layer: "ISO 7816-4 APDU layer",
    category: "File management",
    specArea: "ISO/IEC 7816-4 / file selection",
    summary: "Selects a file, DF, or application context.",
    match: (apdu) => (apdu.ins.value === 0xa4 && classMatches(apdu, "interindustry") ? { score: 60, confidence: "confirmed" } : null),
    decode: decodeSelect,
  },
  {
    id: "iso.status",
    name: "STATUS",
    layer: "ISO 7816-4 APDU layer",
    category: "Status",
    specArea: "ISO/IEC 7816-4 / status",
    summary: "Retrieves status information for the current logical context.",
    match: (apdu) => (apdu.ins.value === 0xf2 && classMatches(apdu, "interindustry") ? { score: 55, confidence: "possible" } : null),
    decode: decodeStatus,
  },
  {
    id: "iso.get-response",
    name: "GET RESPONSE",
    layer: "ISO 7816-4 APDU layer",
    category: "Response retrieval",
    specArea: "ISO/IEC 7816-4 / response chaining",
    summary: "Retrieves response data indicated by a previous status word.",
    match: (apdu) => (apdu.ins.value === 0xc0 && classMatches(apdu, "interindustry") ? { score: 75, confidence: "confirmed" } : null),
    decode: decodeGetResponse,
  },
  {
    id: "iso.get-data",
    name: "GET DATA",
    layer: "ISO 7816-4 APDU layer",
    category: "Data management",
    specArea: "ISO/IEC 7816-4 / data object retrieval",
    summary: "Reads a tagged data object from the current security/application context.",
    match: (apdu) => (apdu.ins.value === 0xca ? { score: classMatches(apdu, "interindustry") ? 70 : 45, confidence: classMatches(apdu, "interindustry") ? "confirmed" : "possible" } : null),
    decode: decodeGetData,
  },
  {
    id: "iso.put-data",
    name: "PUT DATA",
    layer: "ISO 7816-4 APDU layer",
    category: "Data management",
    specArea: "ISO/IEC 7816-4 / data object update",
    summary: "Writes or personalizes a data object identified by P1/P2.",
    match: (apdu) => (apdu.ins.value === 0xda || apdu.ins.value === 0xdb ? { score: 72, confidence: "confirmed" } : null),
    decode: decodePutData,
  },
  {
    id: "iso.deactivate-file",
    name: "DEACTIVATE FILE",
    layer: "ISO 7816-4 APDU layer",
    category: "File administration",
    specArea: "ISO/IEC 7816-4 / file lifecycle administration",
    summary: "Deactivates the selected file or file object.",
    match: (apdu) => (apdu.ins.value === 0x04 && classMatches(apdu, "interindustry") ? { score: 66, confidence: "confirmed" } : null),
    decode: (apdu) => decodeFileAdministration(apdu, "DEACTIVATE FILE"),
  },
  {
    id: "iso.activate-file",
    name: "ACTIVATE FILE",
    layer: "ISO 7816-4 APDU layer",
    category: "File administration",
    specArea: "ISO/IEC 7816-4 / file lifecycle administration",
    summary: "Activates or rehabilitates the selected file.",
    match: (apdu) => (apdu.ins.value === 0x44 && classMatches(apdu, "interindustry") ? { score: 66, confidence: "confirmed" } : null),
    decode: (apdu) => decodeFileAdministration(apdu, "ACTIVATE FILE"),
  },
  {
    id: "iso.create-file",
    name: "CREATE FILE",
    layer: "ISO 7816-4 APDU layer",
    category: "File administration",
    specArea: "ISO/IEC 7816-4 / file creation",
    summary: "Creates a file object using administrative file-control data.",
    match: (apdu) => (apdu.ins.value === 0xe0 && classMatches(apdu, "interindustry") ? { score: 82, confidence: "confirmed" } : null),
    decode: (apdu) => decodeFileAdministration(apdu, "CREATE FILE"),
  },
  {
    id: "iso.delete-file",
    name: "DELETE FILE",
    layer: "ISO 7816-4 APDU layer",
    category: "File administration",
    specArea: "ISO/IEC 7816-4 / file deletion",
    summary: "Deletes a file object in interindustry/UICC file-system context.",
    match: (apdu) => (apdu.ins.value === 0xe4 && classMatches(apdu, "interindustry") ? { score: 81, confidence: "confirmed" } : null),
    decode: (apdu) => decodeFileAdministration(apdu, "DELETE FILE"),
  },
  {
    id: "iso.manage-channel",
    name: "MANAGE CHANNEL",
    layer: "ISO 7816-4 APDU layer",
    category: "Logical channel management",
    specArea: "ISO/IEC 7816-4 / logical channels",
    summary: "Opens or closes a logical channel.",
    match: (apdu) => (apdu.ins.value === 0x70 ? { score: 75, confidence: "confirmed" } : null),
    decode: decodeManageChannel,
  },
  {
    id: "iso.read-binary",
    name: "READ BINARY",
    layer: "ISO 7816-4 APDU layer",
    category: "Binary file access",
    specArea: "ISO/IEC 7816-4 / transparent EF access",
    summary: "Reads bytes from a transparent EF.",
    match: (apdu) => (apdu.ins.value === 0xb0 ? { score: 70, confidence: "confirmed" } : null),
    decode: decodeReadBinary,
  },
  {
    id: "iso.update-binary",
    name: "UPDATE BINARY",
    layer: "ISO 7816-4 APDU layer",
    category: "Binary file access",
    specArea: "ISO/IEC 7816-4 / transparent EF update",
    summary: "Writes bytes into a transparent EF.",
    match: (apdu) => (apdu.ins.value === 0xd6 ? { score: 70, confidence: "confirmed" } : null),
    decode: decodeUpdateBinary,
  },
  {
    id: "iso.read-record",
    name: "READ RECORD",
    layer: "ISO 7816-4 APDU layer",
    category: "Record file access",
    specArea: "ISO/IEC 7816-4 / record EF access",
    summary: "Reads one record from the selected record-oriented EF.",
    match: (apdu) => (apdu.ins.value === 0xb2 ? { score: 72, confidence: "confirmed" } : null),
    decode: (apdu) => decodeRecordAccess(apdu, "Read"),
  },
  {
    id: "iso.update-record",
    name: "UPDATE RECORD",
    layer: "ISO 7816-4 APDU layer",
    category: "Record file access",
    specArea: "ISO/IEC 7816-4 / record EF update",
    summary: "Writes one record in the selected record-oriented EF.",
    match: (apdu) => (apdu.ins.value === 0xdc ? { score: 72, confidence: "confirmed" } : null),
    decode: (apdu) => decodeRecordAccess(apdu, "Update"),
  },
  {
    id: "iso.search-record",
    name: "SEARCH RECORD",
    layer: "ISO 7816-4 APDU layer",
    category: "Record file access",
    specArea: "ISO/IEC 7816-4 / record searching",
    summary: "Searches records matching a provided pattern.",
    match: (apdu) => (apdu.ins.value === 0xa2 ? { score: 68, confidence: "confirmed" } : null),
    decode: decodeSearchRecord,
  },
  {
    id: "iso.verify",
    name: "VERIFY PIN",
    layer: "ISO 7816-4 APDU layer",
    category: "Security",
    specArea: "ISO/IEC 7816-4 / reference data verification",
    summary: "Verifies reference data such as a PIN or CHV.",
    match: (apdu) => (apdu.ins.value === 0x20 ? { score: 72, confidence: "confirmed" } : null),
    decode: (apdu) => decodePin(apdu, "VERIFY"),
  },
  {
    id: "iso.change-reference",
    name: "CHANGE PIN",
    layer: "ISO 7816-4 APDU layer",
    category: "Security",
    specArea: "ISO/IEC 7816-4 / reference data administration",
    summary: "Changes a stored PIN or CHV reference.",
    match: (apdu) => (apdu.ins.value === 0x24 ? { score: 72, confidence: "confirmed" } : null),
    decode: (apdu) => decodePin(apdu, "CHANGE"),
  },
  {
    id: "iso.disable",
    name: "DISABLE PIN",
    layer: "ISO 7816-4 APDU layer",
    category: "Security",
    specArea: "ISO/IEC 7816-4 / reference data administration",
    summary: "Disables a PIN/CHV requirement.",
    match: (apdu) => (apdu.ins.value === 0x26 ? { score: 72, confidence: "confirmed" } : null),
    decode: (apdu) => decodePin(apdu, "DISABLE"),
  },
  {
    id: "iso.enable",
    name: "ENABLE PIN",
    layer: "ISO 7816-4 APDU layer",
    category: "Security",
    specArea: "ISO/IEC 7816-4 / reference data administration",
    summary: "Enables a PIN/CHV requirement.",
    match: (apdu) => (apdu.ins.value === 0x28 ? { score: 72, confidence: "confirmed" } : null),
    decode: (apdu) => decodePin(apdu, "ENABLE"),
  },
  {
    id: "iso.unblock",
    name: "UNBLOCK PIN",
    layer: "ISO 7816-4 APDU layer",
    category: "Security",
    specArea: "ISO/IEC 7816-4 / reference data administration",
    summary: "Unblocks and typically resets a PIN/CHV reference.",
    match: (apdu) => (apdu.ins.value === 0x2c ? { score: 72, confidence: "confirmed" } : null),
    decode: (apdu) => decodePin(apdu, "UNBLOCK"),
  },
  {
    id: "iso.increase",
    name: "INCREASE",
    layer: "ISO 7816-4 APDU layer",
    category: "Value operations",
    specArea: "ISO/IEC 7816-4 / value data updates",
    summary: "Requests a value increment operation.",
    match: (apdu) => (apdu.ins.value === 0x32 ? { score: 60, confidence: "possible" } : null),
    decode: decodeIncrease,
  },
  {
    id: "iso.authenticate",
    name: "AUTHENTICATE",
    layer: "ISO 7816-4 APDU layer",
    category: "Security / authentication",
    specArea: "ISO/IEC 7816-4 / authentication",
    summary: "Requests card-side authentication or cryptographic processing.",
    match: (apdu) => (apdu.ins.value === 0x88 ? { score: 60, confidence: "possible" } : null),
    decode: decodeAuthenticate,
  },
];
