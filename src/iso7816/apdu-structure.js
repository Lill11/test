import { bytesToHex, bytesToSpacedHex, toHex } from "../core/hex.js";

function decodeCla(claByte) {
  const isoChannel = (claByte & 0x40) === 0 ? claByte & 0x03 : 4 + (claByte & 0x0f);
  const secureMessagingBits = claByte & 0x20;
  const chainingBit = claByte & 0x10;
  const proprietaryClass = (claByte & 0x80) !== 0;

  return {
    value: claByte,
    hex: toHex(claByte),
    logicalChannel: isoChannel,
    secureMessaging: secureMessagingBits !== 0,
    commandChaining: chainingBit !== 0,
    classType: proprietaryClass ? "Proprietary / application-specific class" : "Interindustry class",
    rawBits: claByte.toString(2).padStart(8, "0"),
  };
}

function analyzeShortBody(body) {
  const lc = body[0];

  if (body.length === 1 + lc) {
    return {
      caseType: "case3s",
      extendedLength: false,
      lc,
      dataBytes: body.slice(1),
      le: null,
      warnings: [],
    };
  }

  if (body.length === 2 + lc) {
    const rawLe = body.at(-1);
    return {
      caseType: "case4s",
      extendedLength: false,
      lc,
      dataBytes: body.slice(1, 1 + lc),
      le: rawLe === 0x00 ? 256 : rawLe,
      warnings: [],
    };
  }

  if (body.length > 2 + lc) {
    return {
      error: `Lc=${lc} but APDU contains ${body.length - 1} byte(s) after Lc; possible extra trailing byte(s) or malformed APDU.`,
    };
  }

  return {
    error: `Lc=${lc} but only ${Math.max(body.length - 1, 0)} data byte(s) are present.`,
  };
}

function analyzeExtendedBody(body) {
  if (body.length < 3) {
    return { error: "Extended APDU header is incomplete after the 0x00 marker." };
  }

  const extValue = (body[1] << 8) | body[2];
  if (body.length === 3) {
    return {
      caseType: "case2e",
      extendedLength: true,
      lc: null,
      dataBytes: [],
      le: extValue === 0 ? 65536 : extValue,
      warnings: [],
    };
  }

  const lc = extValue;
  if (body.length === 3 + lc) {
    return {
      caseType: "case3e",
      extendedLength: true,
      lc,
      dataBytes: body.slice(3),
      le: null,
      warnings: [],
    };
  }

  if (body.length === 5 + lc) {
    const rawLe = (body.at(-2) << 8) | body.at(-1);
    return {
      caseType: "case4e",
      extendedLength: true,
      lc,
      dataBytes: body.slice(3, 3 + lc),
      le: rawLe === 0 ? 65536 : rawLe,
      warnings: [],
    };
  }

  if (body.length > 5 + lc) {
    return {
      error: `Extended Lc=${lc} but APDU contains ${body.length - 3} byte(s) after the length field; possible extra trailing byte(s) or malformed APDU.`,
    };
  }

  return {
    error: `Extended Lc=${lc} but only ${Math.max(body.length - 3, 0)} data byte(s) are present after the length field.`,
  };
}

export function parseCommandApdu(bytes) {
  if (bytes.length < 4) {
    return {
      ok: false,
      error: "APDU is too short to contain CLA/INS/P1/P2.",
    };
  }

  const header = bytes.slice(0, 4);
  const body = bytes.slice(4);
  const warnings = [];
  let parsedBody;

  if (body.length === 0) {
    parsedBody = { caseType: "case1", extendedLength: false, lc: null, dataBytes: [], le: null, warnings: [] };
  } else if (body.length === 1) {
    const rawLe = body[0];
    parsedBody = {
      caseType: "case2s",
      extendedLength: false,
      lc: null,
      dataBytes: [],
      le: rawLe === 0x00 ? 256 : rawLe,
      warnings: [],
    };
  } else if (body[0] === 0x00) {
    parsedBody = analyzeExtendedBody(body);
  } else {
    parsedBody = analyzeShortBody(body);
  }

  if (parsedBody.error) {
    return { ok: false, error: parsedBody.error };
  }

  warnings.push(...parsedBody.warnings);

  const dataField = {
    bytes: parsedBody.dataBytes,
    hex: bytesToHex(parsedBody.dataBytes),
    spacedHex: bytesToSpacedHex(parsedBody.dataBytes),
  };

  return {
    ok: true,
    bytes,
    rawApdu: bytesToSpacedHex(bytes),
    normalizedHex: bytesToHex(bytes),
    caseType: parsedBody.caseType,
    extendedLength: parsedBody.extendedLength,
    cla: decodeCla(header[0]),
    ins: { value: header[1], hex: toHex(header[1]) },
    p1: header[2],
    p2: header[3],
    p1Hex: toHex(header[2]),
    p2Hex: toHex(header[3]),
    lc: parsedBody.lc,
    data: dataField,
    le: parsedBody.le,
    headerBytes: header,
    bodyBytes: body,
    warnings,
  };
}
