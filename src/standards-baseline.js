export const standardsBaseline = {
  etsi102221: {
    id: "etsi102221",
    label: "ETSI TS 102 221",
    version: "V18.3.0 (2025-10)",
    scope: "UICC-terminal interface and UICC file-system command/response decoding",
    sourceNote: "Latest ETSI Release 18 public UICC-terminal interface baseline used for UICC-specific tables.",
  },
  etsi102223Cat: {
    id: "etsi102223Cat",
    label: "ETSI TS 102 223",
    version: "V17.3.0 (Release 17 baseline)",
    scope: "CAT / USAT proactive command type and qualifier decoding",
    sourceNote:
      "Project-pinned proactive command baseline. Release 17 evidence was cross-checked against ETSI Release 17 material and Wireshark CAT dissector behavior.",
  },
  ts31111: {
    id: "ts31111",
    label: "3GPP TS 31.111",
    version: "V17.14.0 (2025-06)",
    scope: "USAT structure and proactive-command procedure alignment for Release 17",
    sourceNote: "Latest ETSI-hosted Release 17 USAT reference used for matching USAT procedure wording.",
  },
  iso7816_4: {
    id: "iso7816_4",
    label: "ISO/IEC 7816-4",
    version: "Interindustry APDU / FCP-FCI-FMD structure baseline",
    scope: "APDU cases, SELECT response templates, file-control data objects, and status-word families",
    sourceNote:
      "Edition-specific clause text is paywalled; implementation is kept edition-neutral and cross-checked against public summaries and Wireshark dissectors.",
  },
  globalPlatform: {
    id: "globalPlatform",
    label: "GlobalPlatform Card Specification",
    version: "Current implementation baseline: v2.3.1; latest public spec observed: v2.4",
    scope: "Card-management APDUs, INSTALL/LOAD/DELETE, SCP-related command families, and registry data",
    sourceNote:
      "Current decoder tables are still conservative and primarily aligned to the v2.3.1 command set; later additions should be audited before claiming full v2.4 semantics.",
  },
};

export function getBaselineLabel(id) {
  const entry = standardsBaseline[id];
  return entry ? `${entry.label} ${entry.version}` : id;
}
