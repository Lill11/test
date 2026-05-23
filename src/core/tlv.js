import { bytesToHex, bytesToSpacedHex, toHex } from "./hex.js";

function decodeLength(bytes, offset) {
  if (offset >= bytes.length) {
    return { error: "Missing TLV length byte." };
  }

  const first = bytes[offset];
  if (first < 0x80) {
    return { value: first, nextOffset: offset + 1, encodedLength: 1 };
  }

  const count = first & 0x7f;
  if (count === 0 || count > 3) {
    return { error: `Unsupported TLV length form 0x${toHex(first)}.` };
  }
  if (offset + count >= bytes.length) {
    return { error: "Incomplete multi-byte TLV length." };
  }

  let value = 0;
  for (let index = 0; index < count; index += 1) {
    value = (value << 8) | bytes[offset + 1 + index];
  }

  return {
    value,
    nextOffset: offset + 1 + count,
    encodedLength: 1 + count,
  };
}

export function parseBerTlvPrefix(bytes, offset = 0) {
  if (offset >= bytes.length) {
    return { error: "Missing TLV tag byte." };
  }

  const start = offset;
  const firstTag = bytes[offset];
  offset += 1;

  const tagBytes = [firstTag];
  if ((firstTag & 0x1f) === 0x1f) {
    while (offset < bytes.length) {
      const nextTagByte = bytes[offset];
      tagBytes.push(nextTagByte);
      offset += 1;
      if ((nextTagByte & 0x80) === 0) {
        break;
      }
    }
  }

  const lengthInfo = decodeLength(bytes, offset);
  if (lengthInfo.error) {
    return { error: lengthInfo.error, tagBytes, tagHex: bytesToHex(tagBytes) };
  }
  offset = lengthInfo.nextOffset;
  const valueEnd = offset + lengthInfo.value;

  return {
    startOffset: start,
    tagBytes,
    tagHex: bytesToHex(tagBytes),
    length: lengthInfo.value,
    encodedLength: tagBytes.length + lengthInfo.encodedLength,
    valueOffset: offset,
    availableValueBytes: bytes.slice(offset),
    isComplete: valueEnd <= bytes.length,
    missingValueBytes: Math.max(0, valueEnd - bytes.length),
  };
}

export function parseBerTlv(bytes, options = {}) {
  const { maxItems = 128 } = options;
  const items = [];
  const warnings = [];
  let offset = 0;
  let itemCount = 0;

  while (offset < bytes.length && itemCount < maxItems) {
    const start = offset;
    const firstTag = bytes[offset];
    offset += 1;
    if (firstTag === undefined) {
      break;
    }

    const tagBytes = [firstTag];
    if ((firstTag & 0x1f) === 0x1f) {
      while (offset < bytes.length) {
        const nextTagByte = bytes[offset];
        tagBytes.push(nextTagByte);
        offset += 1;
        if ((nextTagByte & 0x80) === 0) {
          break;
        }
      }
    }

    const lengthInfo = decodeLength(bytes, offset);
    if (lengthInfo.error) {
      warnings.push(`TLV parse stopped at offset ${start}: ${lengthInfo.error}`);
      break;
    }
    offset = lengthInfo.nextOffset;
    const valueEnd = offset + lengthInfo.value;
    if (valueEnd > bytes.length) {
      warnings.push(
        `TLV parse stopped at offset ${start}: declared length ${lengthInfo.value} exceeds remaining ${bytes.length - offset} byte(s).`,
      );
      break;
    }

    const valueBytes = bytes.slice(offset, valueEnd);
    offset = valueEnd;
    const tlvBytes = bytes.slice(start, valueEnd);
    items.push({
      kind: "ber",
      tagHex: bytesToHex(tagBytes),
      tagClass:
        (firstTag & 0xc0) === 0x00
          ? "Universal"
          : (firstTag & 0xc0) === 0x40
            ? "Application"
            : (firstTag & 0xc0) === 0x80
              ? "Context-specific"
              : "Private",
      constructed: (firstTag & 0x20) !== 0,
      length: lengthInfo.value,
      startOffset: start,
      endOffset: valueEnd - 1,
      tlvBytes,
      tlvHex: bytesToHex(tlvBytes),
      tlvSpacedHex: bytesToSpacedHex(tlvBytes),
      valueBytes,
      valueHex: bytesToHex(valueBytes),
    });
    itemCount += 1;
  }

  if (itemCount >= maxItems) {
    warnings.push("TLV parsing stopped because the safety item limit was reached.");
  }

  return { items, warnings, bytesConsumed: offset, isComplete: offset === bytes.length };
}

export function parseCatTlv(bytes, options = {}) {
  const { maxItems = 128 } = options;
  const items = [];
  const warnings = [];
  let offset = 0;
  let itemCount = 0;

  while (offset < bytes.length && itemCount < maxItems) {
    const start = offset;
    const rawTag = bytes[offset];
    if (rawTag === undefined) {
      break;
    }
    offset += 1;

    const lengthInfo = decodeLength(bytes, offset);
    if (lengthInfo.error) {
      warnings.push(`CAT TLV parse stopped at offset ${start}: ${lengthInfo.error}`);
      break;
    }
    offset = lengthInfo.nextOffset;
    const valueEnd = offset + lengthInfo.value;
    if (valueEnd > bytes.length) {
      warnings.push(
        `CAT TLV parse stopped at offset ${start}: declared length ${lengthInfo.value} exceeds remaining ${bytes.length - offset} byte(s).`,
      );
      break;
    }

    const valueBytes = bytes.slice(offset, valueEnd);
    offset = valueEnd;
    const tlvBytes = bytes.slice(start, valueEnd);

    items.push({
      kind: "cat",
      rawTag,
      tagNumber: rawTag & 0x7f,
      tagHex: toHex(rawTag),
      comprehensionRequired: (rawTag & 0x80) !== 0,
      length: lengthInfo.value,
      startOffset: start,
      endOffset: valueEnd - 1,
      tlvBytes,
      tlvHex: bytesToHex(tlvBytes),
      tlvSpacedHex: bytesToSpacedHex(tlvBytes),
      valueBytes,
      valueHex: bytesToHex(valueBytes),
    });
    itemCount += 1;
  }

  if (itemCount >= maxItems) {
    warnings.push("CAT TLV parsing stopped because the safety item limit was reached.");
  }

  return { items, warnings, bytesConsumed: offset, isComplete: offset === bytes.length };
}
