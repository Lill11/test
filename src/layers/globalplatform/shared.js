import { bytesToHex, bytesToSpacedHex, toHex } from "../../core/hex.js";
import { field, warning } from "../../core/format.js";
import { parseBerTlv } from "../../core/tlv.js";

export const GP_INSTALL_TYPES = {
  0x02: "INSTALL [for load]",
  0x04: "INSTALL [for install]",
  0x08: "INSTALL [for make selectable]",
  0x0c: "INSTALL [for install and make selectable]",
  0x10: "INSTALL [for extradition]",
  0x20: "INSTALL [for personalization]",
  0x40: "INSTALL [for registry update]",
};

export const GP_GET_STATUS_P1 = {
  0x80: "Issuer Security Domain",
  0x40: "Application / applet instances",
  0x20: "Executable Load Files",
  0x10: "Executable Load File modules",
};

const GP_PRIVILEGE_BYTES = [
  [
    [0x80, "Security Domain"],
    [0x40, "DAP verification"],
    [0x20, "Delegated management"],
    [0x10, "Card lock"],
    [0x08, "Card terminate"],
    [0x04, "Card reset"],
    [0x02, "CVM management"],
    [0x01, "Mandated DAP verification"],
  ],
  [
    [0x80, "Trusted Path"],
    [0x40, "Authorized Management"],
    [0x20, "Token Verification"],
    [0x10, "Global Delete"],
    [0x08, "Global Lock"],
    [0x04, "Global Registry"],
    [0x02, "Final Application"],
    [0x01, "Global Service"],
  ],
  [
    [0x80, "Receipt Generation"],
    [0x40, "Ciphered Load File Data Block"],
    [0x20, "Contactless Activation"],
    [0x10, "Contactless Self-Activation"],
  ],
];

const INSTALL_PARAMETER_TAGS = {
  C6: "Non volatile code space limit",
  C7: "Volatile data space limit",
  C8: "Non volatile data space limit",
  C9: "Application Specific Parameters",
  EF: "System Specific Parameters",
  "5F20": "Provider identifier",
  CF: "Implicit selection parameter",
  B6: "Control Reference Template for Digital Signature",
  "42": "Security Domain identification number",
  CB: "Global service parameters",
};

export function decodeSecurityLevel(p1) {
  const meanings = [];
  if (p1 & 0x01) {
    meanings.push("C-MAC");
  }
  if (p1 & 0x02) {
    meanings.push("C-DECRYPTION");
  }
  if (p1 & 0x04) {
    meanings.push("R-MAC");
  }
  if (p1 & 0x08) {
    meanings.push("R-ENCRYPTION");
  }
  return meanings.length ? meanings.join(", ") : "No secure messaging level bits set";
}

export function parseGpPrivileges(bytes) {
  if (!bytes.length) {
    return {
      labels: ["None"],
      rawHex: "",
      summary: "None",
      warnings: [],
    };
  }

  const labels = [];
  const warnings = [];
  for (let index = 0; index < bytes.length; index += 1) {
    const byteValue = bytes[index];
    const table = GP_PRIVILEGE_BYTES[index];
    if (!table) {
      warnings.push(`Additional privilege byte #${index + 1} is present but not specifically mapped.`);
      labels.push(`Privilege byte ${index + 1}: 0x${toHex(byteValue)}`);
      continue;
    }
    for (const [mask, name] of table) {
      if ((byteValue & mask) !== 0) {
        labels.push(name);
      }
    }
  }

  return {
    labels: labels.length ? labels : ["No recognized privilege flags set"],
    rawHex: bytesToHex(bytes),
    summary: labels.length ? labels.join(", ") : "No recognized privilege flags set",
    warnings,
  };
}

function decodeMemoryLimit(valueBytes) {
  if (valueBytes.length !== 2 && valueBytes.length !== 4) {
    return `${bytesToHex(valueBytes)} (non-standard encoded size)`;
  }
  let value = 0;
  for (const byteValue of valueBytes) {
    value = (value << 8) | byteValue;
  }
  return `${value} byte(s)`;
}

function decodeImplicitSelection(valueBytes) {
  if (!valueBytes.length) {
    return "No implicit selection flags";
  }
  const flags = [];
  const byteValue = valueBytes[0];
  if (byteValue & 0x80) {
    flags.push("Contact interface");
  }
  if (byteValue & 0x40) {
    flags.push("Contactless interface");
  }
  if (byteValue & 0x20) {
    flags.push("Logical channel independent");
  }
  return flags.length ? flags.join(", ") : `Raw flags 0x${toHex(byteValue)}`;
}

function decodeInstallParameterItem(item, fields, summaryEntries, warningsList, prefix = "") {
  const label = INSTALL_PARAMETER_TAGS[item.tagHex] || `Install parameter tag 0x${item.tagHex}`;
  fields.push(field(`${prefix}${label} TLV`, item.tlvSpacedHex || item.tlvHex));
  fields.push(field(`${prefix}${label} tag`, `0x${item.tagHex}`));
  fields.push(field(`${prefix}${label} length`, `${item.length} byte(s)`));

  if (item.tagHex === "C6" || item.tagHex === "C7" || item.tagHex === "C8") {
    const decoded = decodeMemoryLimit(item.valueBytes);
    fields.push(field(`${prefix}${label}`, decoded));
    summaryEntries.push(`${label}: ${decoded}`);
    return;
  }

  if (item.tagHex === "C9") {
    fields.push(field(`${prefix}${label}`, bytesToSpacedHex(item.valueBytes) || "Empty"));
    summaryEntries.push("Application Specific Parameters present");
    return;
  }

  if (item.tagHex === "5F20") {
    const provider = bytesToSpacedHex(item.valueBytes) || "Empty";
    fields.push(field(`${prefix}${label}`, provider));
    summaryEntries.push(`Provider identifier: ${provider}`);
    return;
  }

  if (item.tagHex === "CF") {
    const decoded = decodeImplicitSelection(item.valueBytes);
    fields.push(field(`${prefix}${label}`, decoded));
    summaryEntries.push(`Implicit selection: ${decoded}`);
    return;
  }

  if (item.tagHex === "EF") {
    const nested = parseBerTlv(item.valueBytes);
    fields.push(field(`${prefix}${label}`, bytesToSpacedHex(item.valueBytes) || "Empty"));
    summaryEntries.push("System Specific Parameters present");
    warningsList.push(...nested.warnings.map((message) => warning(message)));
    for (const nestedItem of nested.items) {
      decodeInstallParameterItem(nestedItem, fields, summaryEntries, warningsList, `${label} / `);
    }
    return;
  }

  fields.push(field(`${prefix}${label}`, bytesToSpacedHex(item.valueBytes) || "Empty"));
  summaryEntries.push(label);
}

export function decodeInstallParameters(bytes) {
  const tlv = parseBerTlv(bytes);
  const fields = [];
  const summaryEntries = [];
  const warningsList = [...tlv.warnings.map((message) => warning(message))];

  for (const item of tlv.items) {
    decodeInstallParameterItem(item, fields, summaryEntries, warningsList);
  }

  return {
    fields,
    summary: summaryEntries.length ? summaryEntries.join("; ") : "No recognized install parameter TLVs",
    warnings: warningsList,
    tlvItems: tlv.items.length,
  };
}

function decodeLifecycleState(valueBytes) {
  if (!valueBytes.length) {
    return "No lifecycle bytes";
  }
  if (valueBytes.length === 1) {
    return `0x${toHex(valueBytes[0])}`;
  }
  return bytesToSpacedHex(valueBytes);
}

export function decodeGpRegistryData(bytes) {
  const ber = parseBerTlv(bytes);
  if (!ber.items.length || !ber.isComplete) {
    return null;
  }

  const entries = [];
  const warningsList = [...ber.warnings.map((message) => warning(message))];

  for (const item of ber.items) {
    if (item.tagHex !== "E3") {
      return null;
    }
    const nested = parseBerTlv(item.valueBytes);
    warningsList.push(...nested.warnings.map((message) => warning(message)));
    const entry = {
      tlvHex: item.tlvHex,
      tlvSpacedHex: item.tlvSpacedHex,
      aid: null,
      lifecycle: null,
      privileges: null,
      tags: [],
    };
    for (const nestedItem of nested.items) {
      entry.tags.push(nestedItem.tagHex);
      if (nestedItem.tagHex === "4F") {
        entry.aid = bytesToHex(nestedItem.valueBytes);
      } else if (nestedItem.tagHex === "9F70") {
        entry.lifecycle = decodeLifecycleState(nestedItem.valueBytes);
      } else if (nestedItem.tagHex === "C5") {
        entry.privileges = parseGpPrivileges(nestedItem.valueBytes);
      }
    }
    entries.push(entry);
  }

  return {
    entries,
    warnings: warningsList,
  };
}

export function decodeInitializeUpdateResponse(bytes) {
  if (bytes.length < 29) {
    return null;
  }

  const keyDiversificationData = bytes.slice(0, 10);
  const keyVersionNumber = bytes[10];
  const scpIdByte = bytes[11];
  const scpParameter = bytes[12];
  const remainder = bytes.slice(13);

  const scpIdentifier =
    scpIdByte === 0x02 ? "SCP02" : scpIdByte === 0x03 ? "SCP03" : scpIdByte === 0x01 ? "SCP01" : null;
  if (!scpIdentifier) {
    return null;
  }

  const result = {
    scpIdentifier,
    keyVersionNumber,
    scpParameter: `0x${toHex(scpParameter)}`,
    keyDiversificationData: bytesToHex(keyDiversificationData),
    sequenceCounter: null,
    cardChallenge: null,
    cardCryptogram: null,
    warnings: [],
  };

  if (scpIdentifier === "SCP02") {
    if (remainder.length !== 16) {
      return null;
    }
    result.sequenceCounter = bytesToHex(remainder.slice(0, 2));
    result.cardChallenge = bytesToHex(remainder.slice(2, 8));
    result.cardCryptogram = bytesToHex(remainder.slice(8, 16));
    return result;
  }

  if (scpIdentifier === "SCP03") {
    if (remainder.length !== 16 && remainder.length !== 19) {
      return null;
    }
    result.cardChallenge = bytesToHex(remainder.slice(0, 8));
    result.cardCryptogram = bytesToHex(remainder.slice(8, 16));
    if (remainder.length === 19) {
      result.sequenceCounter = bytesToHex(remainder.slice(16, 19));
    }
    return result;
  }

  return null;
}
