import { field, section } from "../../core/format.js";
import { addCommonApduSection } from "../shared.js";
import { decodeCatPayload } from "./shared.js";

const terminalProfileCapabilities = [
  { byte: 0, mask: 0x80, name: "Profile download" },
  { byte: 0, mask: 0x40, name: "SMS-PP data download" },
  { byte: 0, mask: 0x20, name: "Cell Broadcast data download" },
  { byte: 0, mask: 0x10, name: "Menu selection" },
  { byte: 0, mask: 0x08, name: "Timer expiration" },
  { byte: 1, mask: 0x80, name: "Command result" },
  { byte: 1, mask: 0x40, name: "Call control by NAA" },
  { byte: 1, mask: 0x20, name: "Cell identity status" },
  { byte: 2, mask: 0x80, name: "Display Text" },
  { byte: 2, mask: 0x40, name: "Get Inkey" },
  { byte: 2, mask: 0x20, name: "Get Input" },
  { byte: 2, mask: 0x10, name: "Play Tone" },
];

function decodeTerminalProfileCapabilities(profileBytes) {
  return terminalProfileCapabilities
    .filter((entry) => profileBytes.length > entry.byte && (profileBytes[entry.byte] & entry.mask) !== 0)
    .map((entry) => entry.name);
}

export const ETSI_102223_COMMANDS = [
  {
    id: "etsi102223.terminal-profile",
    name: "TERMINAL PROFILE",
    layer: "ETSI TS 102 223 / 3GPP TS 31.111 CAT/USAT layer",
    category: "CAT / USAT",
    specArea: "ETSI TS 102 223 / terminal capabilities download",
    summary: "Downloads the terminal profile capability bytes to the UICC.",
    match: (apdu) => (apdu.ins.value === 0x10 && (apdu.cla.value & 0x80) === 0x80 ? { score: 92, confidence: "confirmed" } : null),
    decode: (apdu) => {
      const profileBytes = apdu.data.bytes;
      const capabilities = decodeTerminalProfileCapabilities(profileBytes);
      const sections = [
        section("Terminal capability profile", [
          field("Profile length", apdu.lc ?? 0),
          field("Profile bytes", apdu.data.spacedHex || "None"),
          field("Recognized capabilities", capabilities.length ? capabilities.join(", ") : "No mapped capability bits set", {
            certainty: capabilities.length ? "possible" : "possible",
          }),
        ]),
      ];
      addCommonApduSection(apdu, sections);
      return {
        sections,
        decodedFields: {
          payloadLength: apdu.lc ?? 0,
          capabilityInterpretation: profileBytes.length ? "Terminal profile bytes present" : "No profile data",
          profileCapabilities: capabilities.join(", ") || "No mapped capability bits set",
        },
      };
    },
  },
  {
    id: "etsi102223.envelope",
    name: "ENVELOPE",
    layer: "ETSI TS 102 223 / 3GPP TS 31.111 CAT/USAT layer",
    category: "CAT / USAT",
    specArea: "ETSI TS 102 223 / toolkit envelope transport",
    summary: "Transfers event download or envelope TLVs from terminal to UICC.",
    match: (apdu) => (apdu.ins.value === 0xc2 ? { score: 90, confidence: "confirmed" } : null),
    decode: (apdu) => decodeCatPayload(apdu, "Envelope payload"),
  },
  {
    id: "etsi102223.fetch",
    name: "FETCH",
    layer: "ETSI TS 102 223 / 3GPP TS 31.111 CAT/USAT layer",
    category: "CAT / USAT",
    specArea: "ETSI TS 102 223 / proactive command retrieval",
    summary: "Requests the next proactive command prepared by the card.",
    match: (apdu) => (apdu.ins.value === 0x12 && (apdu.cla.value & 0x80) === 0x80 ? { score: 92, confidence: "confirmed" } : null),
    decode: (apdu) => {
      const sections = [
        section("FETCH semantics", [
          field("Requested proactive length", apdu.le === null ? "Not present" : `${apdu.le} byte(s)`),
          field("Proactive command type", "Not visible in the C-APDU alone; inspect the paired response APDU for command TLVs.", {
            certainty: "possible",
          }),
        ]),
      ];
      addCommonApduSection(apdu, sections);
      return {
        sections,
        decodedFields: {
          requestedLength: apdu.le ?? "Not present",
          proactiveCommandType: "Requires FETCH response APDU",
        },
      };
    },
  },
  {
    id: "etsi102223.terminal-response",
    name: "TERMINAL RESPONSE",
    layer: "ETSI TS 102 223 / 3GPP TS 31.111 CAT/USAT layer",
    category: "CAT / USAT",
    specArea: "ETSI TS 102 223 / proactive command result return",
    summary: "Returns the terminal's result for a proactive UICC command.",
    match: (apdu) => (apdu.ins.value === 0x14 && (apdu.cla.value & 0x80) === 0x80 ? { score: 92, confidence: "confirmed" } : null),
    decode: (apdu) => decodeCatPayload(apdu, "Terminal response payload"),
  },
];
