import { bytesToSpacedHex, toHex } from "../core/hex.js";
import { field, section, warning } from "../core/format.js";

export function classMatches(apdu, mode = "any") {
  if (mode === "interindustry") {
    return apdu.cla.classType === "Interindustry class";
  }
  if (mode === "proprietary") {
    return apdu.cla.classType !== "Interindustry class";
  }
  return true;
}

export function byteLabel(byte) {
  return `0x${toHex(byte)}`;
}

export function dataSection(apdu, title = "Data") {
  return section(title, [
    field("Length", apdu.lc ?? 0),
    field("Bytes", apdu.data.spacedHex || "None"),
  ]);
}

export function addCommonApduSection(apdu, sections) {
  sections.unshift(
    section("APDU structure", [
      field("CLA", `0x${apdu.cla.hex} (${apdu.cla.classType})`),
      field("INS", `0x${apdu.ins.hex}`),
      field("P1", `0x${apdu.p1Hex}`),
      field("P2", `0x${apdu.p2Hex}`),
      field("Case", apdu.caseType),
      field("Lc", apdu.lc === null ? "Not present" : apdu.lc),
      field("Le", apdu.le === null ? "Not present" : apdu.le),
    ]),
  );
}

export function decodeAidList(bytes) {
  const aids = [];
  let offset = 0;
  while (offset < bytes.length) {
    const length = bytes[offset];
    offset += 1;
    if (length === undefined) {
      break;
    }
    if (offset + length > bytes.length) {
      return {
        aids,
        warning: `AID list is truncated: length ${length} exceeds remaining ${bytes.length - offset} byte(s).`,
      };
    }
    const value = bytes.slice(offset, offset + length);
    offset += length;
    aids.push({ length, value, hex: value.map((byte) => toHex(byte)).join("") });
  }
  return { aids, warning: null };
}

export function decodeLengthPrefixedFields(bytes, count) {
  const values = [];
  let offset = 0;

  for (let index = 0; index < count; index += 1) {
    if (offset >= bytes.length) {
      return { values, remainder: [], error: `Missing length-prefixed field #${index + 1}.` };
    }
    const length = bytes[offset];
    offset += 1;
    if (offset + length > bytes.length) {
      return {
        values,
        remainder: bytes.slice(offset - 1),
        error: `Field #${index + 1} declares ${length} byte(s) but only ${bytes.length - offset} remain.`,
      };
    }
    const value = bytes.slice(offset, offset + length);
    offset += length;
    values.push({ length, value, hex: value.map((byte) => toHex(byte)).join("") });
  }

  return { values, remainder: bytes.slice(offset), error: null };
}

export function matchByClaFamily(apdu, family) {
  const cla = apdu.cla.value;
  if (family === "gp") {
    return (cla & 0x80) === 0x80;
  }
  if (family === "cat") {
    return (cla & 0x80) === 0x80;
  }
  if (family === "iso") {
    return apdu.cla.classType === "Interindustry class";
  }
  return true;
}

export function unsupportedCaseWarning(apdu, allowedCases) {
  if (!allowedCases.includes(apdu.caseType)) {
    return warning(`Command is uncommon in ${apdu.caseType}; verify that the body structure matches the intended specification context.`);
  }
  return null;
}

export function valueHex(bytes) {
  return bytesToSpacedHex(bytes);
}
