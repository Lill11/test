import { bytesToHex, bytesToSpacedHex } from "./core/hex.js";
import { field, section, warning } from "./core/format.js";
import { parseBerTlv } from "./core/tlv.js";
import { splitResponseApdu } from "./iso7816/status-words.js";
import { decodeProactiveCommandTemplate } from "./layers/etsi102223/shared.js";
import { decodeManageLsiPayload } from "./layers/etsi102221/manage-lsi.js";
import { decodeGlobalPlatformResponse } from "./layers/globalplatform/responses.js";

function decodeGenericBerPayload(bytes, title) {
  const ber = parseBerTlv(bytes);
  const fields = ber.items.map((item) =>
    field(`Tag ${item.tagHex}`, `${item.valueHex || "empty"} (${item.length} byte(s))`, {
      certainty: "possible",
    }),
  );
  return {
    sections: [
      section(title, [
        field("Payload length", bytes.length),
        field("BER-TLV items", ber.items.length),
        field("Payload bytes", bytesToSpacedHex(bytes) || "None"),
      ]),
      section("BER-TLV tree", fields.length ? fields : [field("TLVs", "No BER-TLV items decoded", { certainty: "possible" })]),
    ],
    warnings: ber.warnings.map((message) => warning(message)),
    decodedFields: {
      tlvItems: ber.items.length,
    },
    ber,
  };
}

export function analyzePayloadLine(bytes) {
  const proactive = decodeProactiveCommandTemplate(bytes);
  if (proactive) {
    return {
      kind: "payload",
      commandName: "Proactive command template",
      category: "CAT / USAT payload",
      layer: "ETSI TS 102 223 / 3GPP TS 31.111 CAT/USAT response decoder layer",
      confidence: "confirmed",
      shortMeaning: "Standalone proactive command BER-TLV template.",
      possibleSpecArea: "ETSI TS 102 223 / proactive command BER-TLV template",
      sections: proactive.sections,
      decodedFields: proactive.decodedFields,
      warnings: proactive.warnings,
    };
  }

  const manageLsi = decodeManageLsiPayload(bytes);
  if (manageLsi) {
    return {
      kind: "payload",
      ...manageLsi,
    };
  }

  const globalPlatform = decodeGlobalPlatformResponse(bytes);
  if (globalPlatform) {
    return {
      kind: "payload",
      ...globalPlatform,
    };
  }

  const ber = parseBerTlv(bytes);
  if (ber.items.length && ber.isComplete) {
    const decoded = decodeGenericBerPayload(bytes, "BER-TLV payload");
    return {
      kind: "payload",
      commandName: "BER-TLV payload",
      category: "Structured payload",
      layer: "Generic payload classifier",
      confidence: "possible",
      shortMeaning: "Line is not a recognized APDU command, but it is structurally valid BER-TLV.",
      possibleSpecArea: "Generic BER-TLV payload",
      sections: decoded.sections,
      decodedFields: decoded.decodedFields,
      warnings: decoded.warnings,
    };
  }

  return {
    kind: "payload",
    commandName: "Unknown payload",
    category: "Unknown payload",
    layer: "Generic payload classifier",
    confidence: "possible",
    shortMeaning: "Line does not match a known APDU command, but raw payload bytes were preserved.",
    possibleSpecArea: "Unknown / proprietary payload",
    sections: [
      section("Raw payload", [
        field("Length", bytes.length),
        field("Bytes", bytesToSpacedHex(bytes)),
      ]),
    ],
    decodedFields: {},
    warnings: [warning("Payload type is not yet recognized; only raw bytes are available.")],
  };
}

export function analyzeResponseLine(bytes) {
  const response = splitResponseApdu(bytes);
  if (!response) {
    return null;
  }

  const warningDetails = [warning(response.meaning, response.severity === "ok" ? "info" : response.severity)];
  let commandName = "Response APDU";
  let category = "Response";
  let layer = "ISO 7816-4 response layer";
  let shortMeaning = "Card response data and status word.";
  let possibleSpecArea = "ISO/IEC 7816-4 response APDU";
  let sections = [];
  let decodedFields = {
    statusWord: response.statusWord,
    statusMeaning: response.meaning,
    responseLength: response.dataBytes.length,
  };

  const proactive = response.dataBytes.length ? decodeProactiveCommandTemplate(response.dataBytes) : null;
  const manageLsi = response.dataBytes.length ? decodeManageLsiPayload(response.dataBytes) : null;
  const globalPlatform = response.dataBytes.length ? decodeGlobalPlatformResponse(response.dataBytes) : null;
  if (proactive) {
    commandName = "FETCH proactive response";
    category = "CAT / USAT response";
    layer = "ETSI TS 102 223 / 3GPP TS 31.111 CAT/USAT response decoder layer";
    shortMeaning = "Response APDU carrying a proactive command template returned by the card, typically after FETCH.";
    possibleSpecArea = "ETSI TS 102 223 / proactive command transfer in FETCH response";
    sections = [
      section("Response APDU", [
        field("Response data length", response.dataBytes.length),
        field("Status word", response.statusWord),
        field("Status meaning", response.meaning),
      ]),
      ...proactive.sections,
    ];
    decodedFields = {
      ...decodedFields,
      ...proactive.decodedFields,
    };
    warningDetails.push(...proactive.warnings);
  } else if (manageLsi) {
    commandName = manageLsi.commandName;
    category = manageLsi.category;
    layer = manageLsi.layer;
    shortMeaning = manageLsi.shortMeaning;
    possibleSpecArea = manageLsi.possibleSpecArea;
    sections = [
      section("Response APDU", [
        field("Response data length", response.dataBytes.length),
        field("Status word", response.statusWord),
        field("Status meaning", response.meaning),
      ]),
      ...manageLsi.sections,
    ];
    decodedFields = {
      ...decodedFields,
      ...manageLsi.decodedFields,
    };
    warningDetails.push(...manageLsi.warnings);
  } else if (globalPlatform) {
    commandName = globalPlatform.commandName;
    category = globalPlatform.category;
    layer = globalPlatform.layer;
    shortMeaning = globalPlatform.shortMeaning;
    possibleSpecArea = globalPlatform.possibleSpecArea;
    sections = [
      section("Response APDU", [
        field("Response data length", response.dataBytes.length),
        field("Status word", response.statusWord),
        field("Status meaning", response.meaning),
      ]),
      ...globalPlatform.sections,
    ];
    decodedFields = {
      ...decodedFields,
      ...globalPlatform.decodedFields,
    };
    warningDetails.push(...globalPlatform.warnings);
  } else if (response.dataBytes.length) {
    const ber = parseBerTlv(response.dataBytes);
    if (ber.items.length && ber.isComplete) {
      const decoded = decodeGenericBerPayload(response.dataBytes, "Response payload");
      commandName = "Response APDU with BER-TLV payload";
      category = "Structured response";
      layer = "Generic response decoder layer";
      shortMeaning = "Response APDU containing a BER-TLV payload.";
      possibleSpecArea = "Generic BER-TLV response payload";
      sections = [
        section("Response APDU", [
          field("Response data length", response.dataBytes.length),
          field("Status word", response.statusWord),
          field("Status meaning", response.meaning),
        ]),
        ...decoded.sections,
      ];
      decodedFields = {
        ...decodedFields,
        ...decoded.decodedFields,
      };
      warningDetails.push(...decoded.warnings);
    } else {
      sections = [
        section("Response APDU", [
          field("Response data length", response.dataBytes.length),
          field("Response data bytes", bytesToSpacedHex(response.dataBytes)),
          field("Status word", response.statusWord),
          field("Status meaning", response.meaning),
        ]),
      ];
      warningDetails.push(
        warning("Response payload is not yet decoded structurally; raw bytes and status word are shown.", "warning"),
      );
    }
  } else {
    sections = [
      section("Response APDU", [
        field("Response data length", 0),
        field("Status word", response.statusWord),
        field("Status meaning", response.meaning),
      ]),
    ];
  }

  return {
    kind: "response-apdu",
    rawApdu: bytesToSpacedHex(bytes),
    normalizedHex: bytesToHex(bytes),
    responseData: {
      bytes: response.dataBytes,
      hex: bytesToHex(response.dataBytes),
      spacedHex: bytesToSpacedHex(response.dataBytes),
    },
    statusWord: response.statusWord,
    commandName,
    category,
    layer,
    confidence: proactive ? "confirmed" : "possible",
    shortMeaning,
    possibleSpecArea,
    sections,
    decodedFields,
    warnings: warningDetails,
  };
}
