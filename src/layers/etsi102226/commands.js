import { parseBerTlv } from "../../core/tlv.js";
import { field, section, warning } from "../../core/format.js";
import { addCommonApduSection } from "../shared.js";

function decodeStoreData(apdu) {
  const tlv = parseBerTlv(apdu.data.bytes);
  const p1Mode = apdu.p1 & 0x80 ? "Last / final block indicated" : "Intermediate or single-block store";
  const p2Mode = apdu.p2 & 0x80 ? "Chained block sequence" : "Standalone or first block";

  const tlvPreviewFields = tlv.items.slice(0, 8).map((item) =>
    field(`TLV ${item.tagHex}`, `${item.valueHex || "empty"} (${item.length} byte(s))`, {
      certainty: "possible",
    }),
  );

  const sections = [
    section("RFM / RAM store semantics", [
      field("P1 mode", p1Mode, { certainty: "possible" }),
      field("P2 mode", p2Mode, { certainty: "possible" }),
      field("Payload length", apdu.lc ?? 0),
      field("Payload bytes", apdu.data.spacedHex || "None"),
      field("BER-TLV items", tlv.items.length),
    ]),
    section("Payload TLV preview", tlvPreviewFields.length ? tlvPreviewFields : [field("TLV preview", "No BER-TLV items decoded", { certainty: "possible" })]),
  ];
  addCommonApduSection(apdu, sections);

  return {
    sections,
    warnings: [
      warning("STORE DATA payload semantics vary across ETSI TS 102 226 remote management, GlobalPlatform, and vendor extensions; decoded TLVs should be interpreted with session context."),
      ...tlv.warnings.map((message) => warning(message)),
    ],
    decodedFields: {
      storeMode: `${p1Mode}; ${p2Mode}`,
      tlvItems: tlv.items.length,
    },
  };
}

export const ETSI_102226_COMMANDS = [
  {
    id: "etsi102226.store-data",
    name: "STORE DATA",
    layer: "ETSI TS 102 226 RFM/RAM layer",
    category: "Remote file / applet management",
    specArea: "ETSI TS 102 226 / remote APDU management",
    summary: "Carries remote management payload blocks into the card.",
    match: (apdu) => (apdu.ins.value === 0xe2 && (apdu.cla.value & 0x80) === 0x80 ? { score: 88, confidence: "possible" } : null),
    decode: decodeStoreData,
  },
];
