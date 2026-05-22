import { parseBerTlv } from "../../core/tlv.js";
import { field, section, warning } from "../../core/format.js";
import { addCommonApduSection, decodeAidList, decodeLengthPrefixedFields } from "../shared.js";
import {
  decodeInstallParameters,
  decodeSecurityLevel,
  GP_GET_STATUS_P1,
  GP_INSTALL_TYPES,
  parseGpPrivileges,
} from "./shared.js";

function decodeInstall(apdu) {
  const parsed = decodeLengthPrefixedFields(apdu.data.bytes, 5);
  const warnings = [];
  const sections = [];
  const installType = GP_INSTALL_TYPES[apdu.p1] || `INSTALL variant P1=0x${apdu.p1Hex}`;

  if (parsed.error) {
    warnings.push(warning(parsed.error, "error"));
  }

  const [loadFileAid, moduleAid, applicationAid, privilegesField, installParametersField] = parsed.values;
  const tokenField = parsed.remainder.length
    ? { length: parsed.remainder[0], value: parsed.remainder.slice(1), hex: parsed.remainder.slice(1).map((byte) => byte.toString(16).toUpperCase().padStart(2, "0")).join("") }
    : null;

  const privilegeInfo = privilegesField ? parseGpPrivileges(privilegesField.value) : null;
  if (privilegeInfo) {
    warnings.push(...privilegeInfo.warnings.map((message) => warning(message)));
  }
  const parameterInfo = installParametersField ? decodeInstallParameters(installParametersField.value) : null;
  if (parameterInfo) {
    warnings.push(...parameterInfo.warnings);
  }

  sections.push(
    section("INSTALL decoding", [
      field("INSTALL subtype", installType, { certainty: GP_INSTALL_TYPES[apdu.p1] ? "confirmed" : "possible" }),
      field("P2 meaning", apdu.p2 === 0x00 ? "No explicit install token / privileges qualifier in P2" : `P2=0x${apdu.p2Hex}`, {
        certainty: "possible",
      }),
      field("ELF AID", loadFileAid?.hex || "Not present"),
      field("Executable module AID", moduleAid?.hex || "Not present"),
      field("Application / instance AID", applicationAid?.hex || "Not present"),
      field("Privileges", privilegeInfo ? privilegeInfo.summary : "Not present"),
      field("Install parameters", installParametersField?.hex || "Not present"),
      field("Install parameter summary", parameterInfo ? parameterInfo.summary : "Not present", {
        certainty: parameterInfo ? "possible" : "possible",
      }),
      field("Install token", tokenField?.hex || "Not present", { certainty: tokenField ? "confirmed" : "possible" }),
    ]),
  );

  if (parameterInfo?.fields.length) {
    sections.push(
      section("INSTALL parameter TLVs", parameterInfo.fields.slice(0, 20)),
    );
  }

  addCommonApduSection(apdu, sections);

  return {
    sections,
    warnings,
    decodedFields: {
      installSubtype: installType,
      installP2Meaning: apdu.p2 === 0x00 ? "No explicit P2 qualifier" : `0x${apdu.p2Hex}`,
      executableLoadFileAid: loadFileAid?.hex || "Not present",
      executableModuleAid: moduleAid?.hex || "Not present",
      applicationAid: applicationAid?.hex || "Not present",
      privileges: privilegeInfo ? privilegeInfo.summary : "Not present",
      installParameterSummary: parameterInfo ? parameterInfo.summary : "Not present",
    },
  };
}

function decodeDelete(apdu) {
  const tlv = parseBerTlv(apdu.data.bytes);
  const aidList = decodeAidList(apdu.data.bytes);
  const warnings = [...tlv.warnings.map((message) => warning(message))];
  if (aidList.warning) {
    warnings.push(warning(aidList.warning));
  }
  const sections = [
    section("DELETE semantics", [
      field("Delete control", `P2=0x${apdu.p2Hex}`),
      field("Payload length", apdu.lc ?? 0),
      field("Raw payload", apdu.data.spacedHex || "None"),
      field("AID-style entries", aidList.aids.map((aid) => aid.hex).join(", ") || "None", {
        certainty: aidList.aids.length ? "possible" : "possible",
      }),
      field("BER-TLV items", tlv.items.length),
    ]),
  ];
  addCommonApduSection(apdu, sections);
  return {
    sections,
    warnings,
    decodedFields: {
      deleteControl: `P2=0x${apdu.p2Hex}`,
      tlvItems: tlv.items.length,
    },
  };
}

function decodeLoad(apdu) {
  const tlv = parseBerTlv(apdu.data.bytes);
  const sections = [
    section("LOAD semantics", [
      field("Load block sequence", apdu.p2),
      field("Final block flag", (apdu.p1 & 0x80) !== 0 ? "Last block indicated" : "More load blocks may follow", {
        certainty: "possible",
      }),
      field("Payload length", apdu.lc ?? 0),
      field("Payload bytes", apdu.data.spacedHex || "None"),
      field("BER-TLV items", tlv.items.length),
    ]),
  ];
  addCommonApduSection(apdu, sections);
  return {
    sections,
    warnings: tlv.warnings.map((message) => warning(message)),
    decodedFields: {
      loadBlockSequence: apdu.p2,
      tlvItems: tlv.items.length,
    },
  };
}

function decodePutKey(apdu) {
  const sections = [
    section("PUT KEY decoding", [
      field("Key version number", apdu.p1),
      field("Key identifier / mode", `P2=0x${apdu.p2Hex}`),
      field("Key data length", apdu.lc ?? 0),
      field("Key data", apdu.data.spacedHex || "None"),
    ]),
  ];
  addCommonApduSection(apdu, sections);
  return {
    sections,
    warnings: [warning("PUT KEY payload formats vary by secure channel protocol and key set format; payload is shown structurally rather than semantically decrypted.")],
    decodedFields: {
      keyVersionNumber: apdu.p1,
      keyIdentifier: `0x${apdu.p2Hex}`,
    },
  };
}

function decodeInitializeUpdate(apdu) {
  const sections = [
    section("Secure channel setup", [
      field("Key version number", apdu.p1),
      field("Key identifier", apdu.p2),
      field("Host challenge length", apdu.lc ?? 0),
      field("Host challenge", apdu.data.spacedHex || "None"),
      field("SCP hint", apdu.lc === 8 ? "Looks like SCP02/03-style 8-byte host challenge" : "Challenge size differs from the most common SCP host challenge length", {
        certainty: apdu.lc === 8 ? "possible" : "possible",
      }),
    ]),
  ];
  addCommonApduSection(apdu, sections);
  return { sections, decodedFields: { keyVersionNumber: apdu.p1, keyIdentifier: apdu.p2, scpHint: apdu.lc === 8 ? "Likely SCP02/SCP03 style host challenge" : "Non-default challenge size" } };
}

function decodeExternalAuthenticate(apdu) {
  const securityLevelMeaning = decodeSecurityLevel(apdu.p1);
  const sections = [
    section("External authentication", [
      field("Security level", `P1=0x${apdu.p1Hex}`),
      field("Security level meaning", securityLevelMeaning, {
        certainty: "possible",
      }),
      field("Qualifier", `P2=0x${apdu.p2Hex}`),
      field("Cryptogram length", apdu.lc ?? 0),
      field("Cryptogram / host auth data", apdu.data.spacedHex || "None"),
    ]),
  ];
  addCommonApduSection(apdu, sections);
  return { sections, decodedFields: { securityLevel: `0x${apdu.p1Hex}`, securityLevelMeaning } };
}

function decodeGetStatus(apdu) {
  const entitySelectorMeaning = GP_GET_STATUS_P1[apdu.p1] || `P1=0x${apdu.p1Hex}`;
  const sections = [
    section("Registry status query", [
      field("Entity selector", `P1=0x${apdu.p1Hex}`),
      field("Entity selector meaning", entitySelectorMeaning, {
        certainty: GP_GET_STATUS_P1[apdu.p1] ? "confirmed" : "possible",
      }),
      field("Response scope", `P2=0x${apdu.p2Hex}`),
      field("Filter data", apdu.data.spacedHex || "None"),
      field("Expected response length", apdu.le === null ? "Not present" : `${apdu.le} byte(s)`),
    ]),
  ];
  addCommonApduSection(apdu, sections);
  return { sections, decodedFields: { entitySelector: `0x${apdu.p1Hex}`, entitySelectorMeaning, responseScope: `0x${apdu.p2Hex}` } };
}

function decodeSetStatus(apdu) {
  const sections = [
    section("Registry status update", [
      field("Entity selector", `P1=0x${apdu.p1Hex}`),
      field("State control", `P2=0x${apdu.p2Hex}`),
      field("Affecting payload length", apdu.lc ?? 0),
      field("Payload", apdu.data.spacedHex || "None"),
    ]),
  ];
  addCommonApduSection(apdu, sections);
  return { sections, decodedFields: { entitySelector: `0x${apdu.p1Hex}`, stateControl: `0x${apdu.p2Hex}` } };
}

function decodeStoreData(apdu) {
  const tlv = parseBerTlv(apdu.data.bytes);
  const sections = [
    section("GlobalPlatform STORE DATA", [
      field("Data block control", `P1=0x${apdu.p1Hex}`),
      field("Block sequence / mode", `P2=0x${apdu.p2Hex}`),
      field("Payload length", apdu.lc ?? 0),
      field("Payload bytes", apdu.data.spacedHex || "None"),
      field("BER-TLV items", tlv.items.length),
    ]),
  ];
  addCommonApduSection(apdu, sections);
  return {
    sections,
    warnings: [
      warning("STORE DATA may represent GlobalPlatform personalization, registry update, or delegated management content depending on session context."),
      ...tlv.warnings.map((message) => warning(message)),
    ],
    decodedFields: { dataBlockControl: `0x${apdu.p1Hex}`, blockSequence: `0x${apdu.p2Hex}` },
  };
}

export const GLOBAL_PLATFORM_COMMANDS = [
  {
    id: "gp.install",
    name: "INSTALL",
    layer: "GlobalPlatform card management layer",
    category: "GlobalPlatform management",
    specArea: "GlobalPlatform Card Specification / INSTALL",
    summary: "Installs, makes selectable, personalizes, or updates registry state for card content.",
    match: (apdu) => (apdu.ins.value === 0xe6 && (apdu.cla.value & 0x80) === 0x80 ? { score: 98, confidence: "confirmed" } : null),
    decode: decodeInstall,
  },
  {
    id: "gp.load",
    name: "LOAD",
    layer: "GlobalPlatform card management layer",
    category: "GlobalPlatform management",
    specArea: "GlobalPlatform Card Specification / LOAD",
    summary: "Transfers load file blocks into the card registry.",
    match: (apdu) => (apdu.ins.value === 0xe8 && (apdu.cla.value & 0x80) === 0x80 ? { score: 98, confidence: "confirmed" } : null),
    decode: decodeLoad,
  },
  {
    id: "gp.delete",
    name: "DELETE",
    layer: "GlobalPlatform card management layer",
    category: "GlobalPlatform management",
    specArea: "GlobalPlatform Card Specification / DELETE",
    summary: "Deletes application, package, or associated registry content.",
    match: (apdu) => (apdu.ins.value === 0xe4 && (apdu.cla.value & 0x80) === 0x80 ? { score: 98, confidence: "confirmed" } : null),
    decode: decodeDelete,
  },
  {
    id: "gp.put-key",
    name: "PUT KEY",
    layer: "GlobalPlatform card management layer",
    category: "GlobalPlatform management",
    specArea: "GlobalPlatform Card Specification / PUT KEY",
    summary: "Replaces or adds secure channel keys in a card key set.",
    match: (apdu) => (apdu.ins.value === 0xd8 && (apdu.cla.value & 0x80) === 0x80 ? { score: 97, confidence: "confirmed" } : null),
    decode: decodePutKey,
  },
  {
    id: "gp.initialize-update",
    name: "INITIALIZE UPDATE",
    layer: "GlobalPlatform card management layer",
    category: "Secure channel",
    specArea: "GlobalPlatform Card Specification / secure channel establishment",
    summary: "Starts a GlobalPlatform secure channel by providing the host challenge.",
    match: (apdu) => (apdu.ins.value === 0x50 && (apdu.cla.value & 0x80) === 0x80 ? { score: 97, confidence: "confirmed" } : null),
    decode: decodeInitializeUpdate,
  },
  {
    id: "gp.external-authenticate",
    name: "EXTERNAL AUTHENTICATE",
    layer: "GlobalPlatform card management layer",
    category: "Secure channel",
    specArea: "GlobalPlatform Card Specification / secure channel establishment",
    summary: "Completes secure channel setup with host cryptogram and security level.",
    match: (apdu) => (apdu.ins.value === 0x82 && (apdu.cla.value & 0x80) === 0x80 ? { score: 97, confidence: "confirmed" } : null),
    decode: decodeExternalAuthenticate,
  },
  {
    id: "gp.get-status",
    name: "GET STATUS",
    layer: "GlobalPlatform card management layer",
    category: "GlobalPlatform management",
    specArea: "GlobalPlatform Card Specification / registry query",
    summary: "Queries registry status for issuers, security domains, packages, or applications.",
    match: (apdu) => (apdu.ins.value === 0xf2 && (apdu.cla.value & 0x80) === 0x80 ? { score: 97, confidence: "confirmed" } : null),
    decode: decodeGetStatus,
  },
  {
    id: "gp.set-status",
    name: "SET STATUS",
    layer: "GlobalPlatform card management layer",
    category: "GlobalPlatform management",
    specArea: "GlobalPlatform Card Specification / lifecycle control",
    summary: "Changes lifecycle state or status of registry entities.",
    match: (apdu) => (apdu.ins.value === 0xf0 && (apdu.cla.value & 0x80) === 0x80 ? { score: 97, confidence: "confirmed" } : null),
    decode: decodeSetStatus,
  },
  {
    id: "gp.store-data",
    name: "STORE DATA",
    layer: "GlobalPlatform card management layer",
    category: "GlobalPlatform management",
    specArea: "GlobalPlatform Card Specification / personalization and registry data",
    summary: "Transfers data blocks used for personalization or management actions.",
    match: (apdu) => (apdu.ins.value === 0xe2 && (apdu.cla.value & 0x80) === 0x80 ? { score: 94, confidence: "possible" } : null),
    decode: decodeStoreData,
  },
];
