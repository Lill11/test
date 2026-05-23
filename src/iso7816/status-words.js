import { toHex } from "../core/hex.js";

export function decodeStatusWord(sw1, sw2) {
  const statusWord = `${toHex(sw1)}${toHex(sw2)}`;
  // Source: ISO/IEC 7816-4 status word families with UICC/CAT-specific additions
  // commonly used on ETSI TS 102 221 / TS 102 223 interfaces.

  if (sw1 === 0x90 && sw2 === 0x00) {
    return { statusWord, severity: "ok", meaning: "Success: normal processing." };
  }
  if (sw1 === 0x91) {
    return {
      statusWord,
      severity: "info",
      meaning: `Success with proactive command pending; FETCH ${sw2 === 0x00 ? "is required" : `should request about ${sw2} byte(s)`}.`,
    };
  }
  if (sw1 === 0x61) {
    return {
      statusWord,
      severity: "info",
      meaning: `Success with more response data available; GET RESPONSE may retrieve ${sw2 === 0x00 ? "up to 256" : sw2} more byte(s).`,
    };
  }
  if (sw1 === 0x62) {
    if (sw2 === 0x81) {
      return { statusWord, severity: "warning", meaning: "Warning: part of returned data may be corrupted." };
    }
    if (sw2 === 0x82) {
      return { statusWord, severity: "warning", meaning: "Warning: end of file or record reached before reading expected data." };
    }
    if (sw2 === 0x83) {
      return { statusWord, severity: "warning", meaning: "Warning: selected file invalidated." };
    }
    return { statusWord, severity: "warning", meaning: "Warning state: returned data may be stale or incomplete." };
  }
  if (sw1 === 0x63) {
    if ((sw2 & 0xf0) === 0xc0) {
      return { statusWord, severity: "warning", meaning: `Verification failed; ${sw2 & 0x0f} retry attempt(s) may remain.` };
    }
    return { statusWord, severity: "warning", meaning: "Warning state: command completed with counter or verification state information." };
  }
  if (sw1 === 0x67 && sw2 === 0x00) {
    return { statusWord, severity: "error", meaning: "Wrong length." };
  }
  if (sw1 === 0x68 && sw2 === 0x81) {
    return { statusWord, severity: "error", meaning: "Logical channel not supported." };
  }
  if (sw1 === 0x68 && sw2 === 0x82) {
    return { statusWord, severity: "error", meaning: "Secure messaging not supported." };
  }
  if (sw1 === 0x68) {
    return { statusWord, severity: "error", meaning: "Requested function in CLA is not supported." };
  }
  if (sw1 === 0x69 && sw2 === 0x82) {
    return { statusWord, severity: "error", meaning: "Security status not satisfied." };
  }
  if (sw1 === 0x69 && sw2 === 0x83) {
    return { statusWord, severity: "error", meaning: "Authentication or method blocked." };
  }
  if (sw1 === 0x69 && sw2 === 0x84) {
    return { statusWord, severity: "error", meaning: "Referenced data invalidated." };
  }
  if (sw1 === 0x69 && sw2 === 0x85) {
    return { statusWord, severity: "error", meaning: "Conditions of use not satisfied." };
  }
  if (sw1 === 0x69 && sw2 === 0x86) {
    return { statusWord, severity: "error", meaning: "Command not allowed; no current EF or required context missing." };
  }
  if (sw1 === 0x69) {
    return { statusWord, severity: "error", meaning: "Command not allowed or blocked by current security / lifecycle state." };
  }
  if (sw1 === 0x6a && sw2 === 0x80) {
    return { statusWord, severity: "error", meaning: "Incorrect parameters in the data field." };
  }
  if (sw1 === 0x6a && sw2 === 0x81) {
    return { statusWord, severity: "error", meaning: "Function not supported." };
  }
  if (sw1 === 0x6a && sw2 === 0x82) {
    return { statusWord, severity: "error", meaning: "File, application, or referenced object not found." };
  }
  if (sw1 === 0x6a && sw2 === 0x83) {
    return { statusWord, severity: "error", meaning: "Record or object not found." };
  }
  if (sw1 === 0x6a && sw2 === 0x84) {
    return { statusWord, severity: "error", meaning: "Not enough memory space in file or object store." };
  }
  if (sw1 === 0x6a && sw2 === 0x86) {
    return { statusWord, severity: "error", meaning: "Incorrect parameters P1/P2." };
  }
  if (sw1 === 0x6a && sw2 === 0x87) {
    return { statusWord, severity: "error", meaning: "Lc inconsistent with P1/P2." };
  }
  if (sw1 === 0x6a && sw2 === 0x88) {
    return { statusWord, severity: "error", meaning: "Referenced data object not found." };
  }
  if (sw1 === 0x6a) {
    return { statusWord, severity: "error", meaning: "Wrong parameters P1/P2 or object reference problem." };
  }
  if (sw1 === 0x6b && sw2 === 0x00) {
    return { statusWord, severity: "error", meaning: "Wrong parameters P1/P2." };
  }
  if (sw1 === 0x6d && sw2 === 0x00) {
    return { statusWord, severity: "error", meaning: "Instruction code not supported or invalid." };
  }
  if (sw1 === 0x6e && sw2 === 0x00) {
    return { statusWord, severity: "error", meaning: "Class not supported." };
  }
  if (sw1 === 0x6f && sw2 === 0x00) {
    return { statusWord, severity: "error", meaning: "No precise diagnosis; internal exception or generic failure." };
  }
  if (sw1 === 0x93 && sw2 === 0x00) {
    return { statusWord, severity: "error", meaning: "Toolkit busy or SIM application toolkit command cannot be processed now." };
  }
  if (sw1 >= 0x64 && sw1 <= 0x6f) {
    return { statusWord, severity: "error", meaning: "Error response in the ISO/IEC 7816-4 status word range." };
  }
  if (sw1 >= 0x90 && sw1 <= 0x9f) {
    return { statusWord, severity: "info", meaning: "Successful or application-specific completion status." };
  }

  return { statusWord, severity: "warning", meaning: "Application-specific or currently unmapped status word." };
}

export function splitResponseApdu(bytes) {
  if (bytes.length < 2) {
    return null;
  }

  const sw1 = bytes.at(-2);
  const sw2 = bytes.at(-1);
  const decoded = decodeStatusWord(sw1, sw2);

  const recognized =
    sw1 === 0x90 ||
    sw1 === 0x91 ||
    sw1 === 0x61 ||
    (sw1 >= 0x62 && sw1 <= 0x6f) ||
    sw1 === 0x93 ||
    sw1 === 0x9e ||
    sw1 === 0x9f;

  if (!recognized) {
    return null;
  }

  return {
    sw1,
    sw2,
    ...decoded,
    dataBytes: bytes.slice(0, -2),
  };
}
