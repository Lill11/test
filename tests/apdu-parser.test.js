import test from "node:test";
import assert from "node:assert/strict";

import { parseApduLine, parseApduText } from "../src/apdu-parser.js";

test("parses a SELECT FILE APDU with contextual decoding", () => {
  const result = parseApduLine("00 A4 04 00 08 A0 00 00 00 87 10 02 FF", 1);

  assert.equal(result.lineNumber, 1);
  assert.equal(result.commandName, "SELECT FILE");
  assert.equal(result.layer, "ISO 7816-4 APDU layer");
  assert.equal(result.category, "File management");
  assert.equal(result.caseType, "case3s");
  assert.equal(result.cla.hex, "00");
  assert.equal(result.ins.hex, "A4");
  assert.equal(result.lc, 8);
  assert.equal(result.data.hex, "A0000000871002FF");
  assert.equal(result.decodedFields.selectionMode, "Select by DF name / AID");
  assert.match(result.decodedFields.selectionReference, /AID/i);
});

test("parses a short case 2 READ BINARY APDU", () => {
  const result = parseApduLine("00 B0 00 00 10", 2);

  assert.equal(result.commandName, "READ BINARY");
  assert.equal(result.caseType, "case2s");
  assert.equal(result.lc, null);
  assert.equal(result.le, 16);
  assert.equal(result.decodedFields.offset, 0);
});

test("parses an extended APDU with Lc and Le", () => {
  const result = parseApduLine("80 E2 00 00 00 00 03 01 02 03 00 10", 3);

  assert.equal(result.commandName, "STORE DATA");
  assert.equal(result.caseType, "case4e");
  assert.equal(result.extendedLength, true);
  assert.equal(result.lc, 3);
  assert.equal(result.le, 16);
  assert.equal(result.data.hex, "010203");
});

test("flags malformed short APDUs with meaningful Lc mismatch warnings", () => {
  const result = parseApduLine("00 A4 04 00 08 A0 00 00", 4);

  assert.equal(result.commandName, "Unknown");
  assert.match(result.warnings.join(" "), /Lc=8/i);
});

test("decodes VERIFY PIN references", () => {
  const result = parseApduLine("00 20 00 01 08 31 32 33 34 FF FF FF FF", 5);

  assert.equal(result.commandName, "VERIFY PIN");
  assert.equal(result.decodedFields.referenceDataQualifier, "PIN/CHV reference 0x01");
  assert.equal(result.decodedFields.pinDataLength, 8);
});

test("decodes GlobalPlatform INSTALL variants and AIDs", () => {
  const result = parseApduLine(
    "80 E6 0C 00 16 08 A0 00 00 00 03 00 00 00 00 00 08 A0 00 00 00 03 00 00 00 01 00 00",
    6,
  );

  assert.equal(result.commandName, "INSTALL");
  assert.equal(result.layer, "GlobalPlatform card management layer");
  assert.match(result.decodedFields.installSubtype, /install and make selectable/i);
  assert.equal(result.decodedFields.executableLoadFileAid, "A000000003000000");
});

test("decodes TERMINAL RESPONSE TLVs and proactive command hints", () => {
  const result = parseApduLine("80 14 00 00 0C 81 03 01 40 00 82 02 82 81 83 01 00", 7);

  assert.equal(result.commandName, "TERMINAL RESPONSE");
  assert.equal(result.layer, "ETSI TS 102 223 / 3GPP TS 31.111 CAT/USAT layer");
  assert.equal(result.decodedFields.proactiveCommandType, "OPEN CHANNEL");
  const tlvValues = result.sections.flatMap((section) => section.fields.map((currentField) => `${currentField.label}:${currentField.value}`));
  assert.ok(tlvValues.some((value) => value.includes("Result TLV:83 01 00")));
  assert.ok(tlvValues.some((value) => value.includes("Device identities TLV:82 02 82 81")));
});

test("supports mixed log lines with APDU-looking byte runs", () => {
  const result = parseApduLine("TX APDU: 00 A4 00 04 02 3F 00", 8);

  assert.equal(result.commandName, "SELECT FILE");
  assert.equal(result.lc, 2);
});

test("parses multi-line input and ignores blank lines", () => {
  const results = parseApduText(`
00 A4 00 04 02 3F 00

80 10 00 00 03 FF FF FF
`);

  assert.equal(results.length, 2);
  assert.equal(results[0].lineNumber, 2);
  assert.equal(results[0].commandName, "SELECT FILE");
  assert.equal(results[1].commandName, "TERMINAL PROFILE");
});

test("decodes terminal profile capability hints", () => {
  const result = parseApduLine("80 10 00 00 03 FF FF FF", 9);

  assert.equal(result.commandName, "TERMINAL PROFILE");
  assert.match(result.decodedFields.profileCapabilities, /Profile download/i);
  assert.match(result.decodedFields.profileCapabilities, /SMS-PP data download/i);
});

test("decodes FETCH response proactive command payloads and status words", () => {
  const result = parseApduLine("D00D8103010300820281828402011E9000", 10);

  assert.equal(result.kind, "response-apdu");
  assert.equal(result.commandName, "FETCH proactive response");
  assert.equal(result.decodedFields.statusWord, "9000");
  assert.equal(result.decodedFields.proactiveCommandType, "POLL INTERVAL");
  assert.equal(result.decodedFields.commandNumber, 1);
  assert.equal(result.decodedFields.durationUnit, "seconds");
  assert.equal(result.decodedFields.durationInterval, 30);
});

test("splits response data from common non-success status words", () => {
  const result = parseApduLine("6F108408A0000001510000006A82", 11);

  assert.equal(result.kind, "response-apdu");
  assert.equal(result.decodedFields.statusWord, "6A82");
  assert.match(result.decodedFields.statusMeaning, /not found/i);
  assert.equal(result.responseData.hex, "6F108408A000000151000000");
});

test("decodes proactive command templates without APDU wrapper", () => {
  const result = parseApduLine("D00D8103010300820281828402011E", 12);

  assert.equal(result.kind, "payload");
  assert.equal(result.commandName, "Proactive command template");
  assert.equal(result.decodedFields.proactiveCommandType, "POLL INTERVAL");
});

test("falls back to BER-TLV payload decoding when a line is not a known APDU", () => {
  const result = parseApduLine("6F0A8408A000000151000000", 13);

  assert.equal(result.kind, "payload");
  assert.equal(result.commandName, "BER-TLV payload");
  assert.equal(result.decodedFields.tlvItems, 1);
});

test("classifies CREATE FILE in interindustry/UICC context", () => {
  const result = parseApduLine("00 E0 00 00 02 62 00", 14);

  assert.equal(result.commandName, "CREATE FILE");
  assert.match(result.layer, /ISO 7816-4|ETSI TS 102 221/i);
});

test("classifies DEACTIVATE FILE in interindustry/UICC context", () => {
  const result = parseApduLine("00 04 00 00", 15);

  assert.equal(result.commandName, "DEACTIVATE FILE");
});

test("decodes GlobalPlatform GET STATUS entity selector", () => {
  const result = parseApduLine("80 F2 40 00 02 4F 00 00", 16);

  assert.equal(result.commandName, "GET STATUS");
  assert.match(result.decodedFields.entitySelectorMeaning, /application|applet/i);
});

test("decodes GlobalPlatform EXTERNAL AUTHENTICATE security level bits", () => {
  const result = parseApduLine("84 82 03 00 08 01 02 03 04 05 06 07 08", 17);

  assert.equal(result.commandName, "EXTERNAL AUTHENTICATE");
  assert.match(result.decodedFields.securityLevelMeaning, /C-MAC/i);
  assert.match(result.decodedFields.securityLevelMeaning, /C-DECRYPTION/i);
});

test("decodes MANAGE LSI configure command with SGP.22 additional TLVs", () => {
  const result = parseApduLine("80 7C 04 00 0D 80 01 02 81 01 01 90 02 01 03 91 01 02 00", 18);

  assert.equal(result.commandName, "MANAGE LSI");
  assert.match(result.decodedFields.operation, /configure lsis/i);
  assert.equal(result.decodedFields.highestProposedLsi, 2);
  assert.match(result.decodedFields.lsiOptionsMeaning, /NAD/i);
  assert.match(result.decodedFields.deviceMepModes, /MEP-A1/i);
  assert.match(result.decodedFields.deviceMepModes, /MEP-B/i);
  assert.equal(result.decodedFields.maxEnabledProfileLsis, 2);
});

test("decodes MANAGE LSI configure response data with SGP.22 TLVs", () => {
  const result = parseApduLine("80010281010190030101039101029000", 19);

  assert.equal(result.kind, "response-apdu");
  assert.equal(result.commandName, "MANAGE LSI response");
  assert.equal(result.decodedFields.manageLsiResponseType, "Configure LSIs response");
  assert.equal(result.decodedFields.highestSupportedLsi, 2);
  assert.match(result.decodedFields.jointlySupportedMepMode, /MEP-A1/i);
  assert.match(result.decodedFields.euiccSupportedMepModes, /MEP-B/i);
  assert.equal(result.decodedFields.jointlySupportedEnabledProfileLsis, 2);
  assert.equal(result.decodedFields.statusWord, "9000");
});

test("decodes GlobalPlatform INSTALL parameter tags more deeply", () => {
  const result = parseApduLine(
    "80 E6 04 00 20 08 A0 00 00 00 03 00 00 00 00 08 A0 00 00 00 03 00 00 01 01 80 09 C9 02 01 02 EF 03 C7 01 10 00",
    20,
  );

  assert.equal(result.commandName, "INSTALL");
  assert.match(result.decodedFields.installSubtype, /for install/i);
  assert.match(result.decodedFields.privileges, /Security Domain/i);
  assert.match(result.decodedFields.installParameterSummary, /Application Specific Parameters/i);
  assert.match(result.decodedFields.installParameterSummary, /Volatile data space limit/i);
});

test("decodes GlobalPlatform INITIALIZE UPDATE response data", () => {
  const result = parseApduLine("000102030405060708090102151234A1A2A3A4A5A601020304050607089000", 21);

  assert.equal(result.kind, "response-apdu");
  assert.equal(result.commandName, "INITIALIZE UPDATE response");
  assert.equal(result.decodedFields.scpIdentifier, "SCP02");
  assert.equal(result.decodedFields.keyVersionNumber, 1);
  assert.equal(result.decodedFields.sequenceCounter, "1234");
  assert.equal(result.decodedFields.statusWord, "9000");
});

test("decodes GlobalPlatform registry-style BER-TLV responses", () => {
  const result = parseApduLine("E30D4F04A00000019F700107C501809000", 22);

  assert.equal(result.kind, "response-apdu");
  assert.equal(result.commandName, "GlobalPlatform registry response");
  assert.equal(result.decodedFields.registryEntries, 1);
  assert.equal(result.decodedFields.firstEntryAid, "A0000001");
  assert.match(result.decodedFields.firstEntryPrivileges, /Security Domain/i);
});
