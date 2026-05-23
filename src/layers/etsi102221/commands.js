import { field, section, warning } from "../../core/format.js";
import { addCommonApduSection } from "../shared.js";
import { decodeManageLsiCommand } from "./manage-lsi.js";
import { decodeTerminalCapabilityCommand } from "./terminal-capability.js";

function decorate(baseDecode, specArea, extraWarnings = []) {
  return (apdu) => {
    const result = baseDecode(apdu);
    return {
      ...result,
      warnings: [...(result.warnings || []), ...extraWarnings.map((message) => warning(message))],
      meaning: result.meaning,
      specArea,
    };
  };
}

export const ETSI_102221_COMMANDS = [
  {
    id: "etsi102221.status",
    name: "STATUS",
    layer: "ETSI TS 102 221 UICC layer",
    category: "UICC file management",
    specArea: "ETSI TS 102 221 / status and current application context",
    summary: "Retrieves status or file control information in a UICC context.",
    match: (apdu) => (apdu.ins.value === 0xf2 && apdu.cla.classType === "Interindustry class" ? { score: 80, confidence: "confirmed" } : null),
    decode: decorate(
      (apdu) => {
        const sections = [
          section("UICC status interpretation", [
            field("Qualifier", `P1=0x${apdu.p1Hex}`),
            field("Response control", `P2=0x${apdu.p2Hex}`),
            field("Requested response size", apdu.le === null ? "Not present" : `${apdu.le} byte(s)`),
          ]),
        ];
        addCommonApduSection(apdu, sections);
        return {
          sections,
          decodedFields: {
            statusMode: `P2=0x${apdu.p2Hex}`,
            requestedLength: apdu.le ?? "Not present",
          },
        };
      },
      "ETSI TS 102 221 / status and current application context",
    ),
  },
  {
    id: "etsi102221.authenticate",
    name: "AUTHENTICATE",
    layer: "ETSI TS 102 221 UICC layer",
    category: "UICC security",
    specArea: "ETSI TS 102 221 / application authentication",
    summary: "Carries UICC authentication challenges or security service requests.",
    match: (apdu) => (apdu.ins.value === 0x88 ? { score: 82, confidence: "confirmed" } : null),
    decode: decorate(
      (apdu) => {
        const sections = [
          section("UICC authentication", [
            field("Context qualifier", `P1=0x${apdu.p1Hex}`),
            field("Authentication method hint", apdu.p2 === 0x80 ? "Common AKA/USIM style qualifier" : `P2=0x${apdu.p2Hex}`, {
              certainty: apdu.p2 === 0x80 ? "confirmed" : "possible",
            }),
            field("Challenge length", apdu.lc ?? 0),
            field("Challenge / payload", apdu.data.spacedHex || "None"),
          ]),
        ];
        addCommonApduSection(apdu, sections);
        return { sections, decodedFields: { challengeLength: apdu.lc ?? 0 } };
      },
      "ETSI TS 102 221 / application authentication",
    ),
  },
  {
    id: "etsi102221.terminal-capability",
    name: "TERMINAL CAPABILITY",
    layer: "ETSI TS 102 221 UICC layer",
    category: "UICC-terminal capability exchange",
    specArea: "ETSI TS 102 221 / terminal capability",
    summary: "Downloads terminal interface and eUICC capability TLVs before application selection.",
    match: (apdu) => (apdu.ins.value === 0xaa && (apdu.cla.value & 0x80) === 0x80 ? { score: 96, confidence: "confirmed" } : null),
    decode: decodeTerminalCapabilityCommand,
  },
  {
    id: "etsi102221.manage-lsi",
    name: "MANAGE LSI",
    layer: "ETSI TS 102 221 UICC layer",
    category: "Vendor / eUICC interface control",
    specArea: "ETSI TS 102 221 / logical secure interfaces",
    summary: "Controls or configures logical secure interfaces on eUICC-capable cards.",
    match: (apdu) => (apdu.ins.value === 0x7c && (apdu.cla.value & 0x80) === 0x80 ? { score: 95, confidence: "confirmed" } : null),
    decode: decodeManageLsiCommand,
  },
];
