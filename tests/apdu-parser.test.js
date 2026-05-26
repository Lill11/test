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
  assert.equal(result.decodedFields.proactiveCommandType, "0x40 — OPEN CHANNEL");
  const tlvValues = result.sections.flatMap((section) => section.fields.map((currentField) => `${currentField.label}:${currentField.value}`));
  assert.ok(tlvValues.some((value) => value.includes("Result TLV:83 01 00")));
  assert.ok(tlvValues.some((value) => value.includes("Device identities TLV:82 02 82 81")));
  assert.ok(tlvValues.some((value) => value.includes("General result code:0x00")));
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
  assert.equal(result.decodedFields.proactiveCommandType, "0x03 — POLL INTERVAL");
  assert.equal(result.decodedFields.commandNumber, 1);
  assert.equal(result.decodedFields.durationUnit, "seconds");
  assert.equal(result.decodedFields.durationInterval, 30);
  assert.equal(result.warningDetails.length, 0);
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
  assert.equal(result.decodedFields.proactiveCommandType, "0x03 — POLL INTERVAL");
});

test("decodes REFRESH command qualifier semantics from 0x00 to 0x0A", () => {
  const expectedModes = new Map([
    [0x00, "NAA Initialization and Full File Change Notification"],
    [0x01, "File Change Notification"],
    [0x02, "NAA Initialization and File Change Notification"],
    [0x03, "NAA Initialization"],
    [0x04, "UICC Reset"],
    [0x05, "NAA Application Reset"],
    [0x06, "NAA Session Reset"],
    [0x07, "Steering of Roaming"],
    [0x08, "Steering of Roaming for I-WLAN"],
    [0x09, "eUICC Profile State Change"],
    [0x0A, "Application Update"],
  ]);

  for (const [qualifier, expectedMeaning] of expectedModes) {
    const hexQualifier = qualifier.toString(16).toUpperCase().padStart(2, "0");
    const result = parseApduLine(`D00981030101${hexQualifier}82028182`, 12);

    assert.equal(result.kind, "payload");
    assert.equal(result.decodedFields.proactiveCommandType, "0x01 — REFRESH");
    assert.equal(result.decodedFields.commandQualifier, qualifier);
    assert.equal(result.decodedFields.commandQualifierMeaning, expectedMeaning);
    const values = result.sections.flatMap((section) => section.fields.map((currentField) => `${currentField.label}:${currentField.value}`));
    assert.ok(!values.some((value) => value.includes(`REFRESH mode:${expectedMeaning}`)));
    assert.ok(!values.some((value) => value.includes("Qualifier behavior category:")));
  }
});

test("decodes FETCH response with REFRESH 0x09 as eUICC Profile State Change", () => {
  const result = parseApduLine("D0098103010109820281829000", 12);

  assert.equal(result.kind, "response-apdu");
  assert.equal(result.commandName, "FETCH proactive response");
  assert.equal(result.decodedFields.proactiveCommandType, "0x01 — REFRESH");
  assert.equal(result.decodedFields.proactiveCommandTypeName, "REFRESH");
  assert.equal(result.decodedFields.proactiveCommandTypeByte, "0x01");
  assert.equal(result.decodedFields.commandQualifierMeaning, "eUICC Profile State Change");
  const values = result.sections.flatMap((section) => section.fields.map((currentField) => `${currentField.label}:${currentField.value}`));
  assert.ok(!values.some((value) => value.includes("REFRESH behavior category:")));
  assert.ok(!values.some((value) => value.includes("Qualifier behavior category:")));
});

test("decodes proactive command type 0x79 as LSI Command / Manage LSI with conservative qualifier wording", () => {
  const result = parseApduLine("D0 09 81 03 01 79 01 82 02 81 82", 13);

  assert.equal(result.kind, "payload");
  assert.equal(result.commandName, "Proactive command template");
  assert.equal(result.decodedFields.proactiveCommandType, "0x79 — LSI Command / Manage LSI");
  assert.equal(result.decodedFields.proactiveCommandTypeName, "LSI Command / Manage LSI");
  assert.equal(result.decodedFields.proactiveCommandTypeByte, "0x79");
  assert.equal(result.decodedFields.commandQualifier, 0x01);
  assert.equal(result.decodedFields.commandQualifierMeaning, "unknown / not decoded yet");
  assert.match(result.decodedFields.proactiveCommandTableVersion, /ETSI TS 102 223 V17\.3\.0/i);
  const values = result.sections.flatMap((section) => section.fields.map((currentField) => `${currentField.label}:${currentField.value}`));
  assert.ok(values.some((value) => value.includes("Proactive command type:0x79 — LSI Command / Manage LSI")));
  assert.ok(!values.some((value) => value.includes("Command type byte:0x79")));
  assert.ok(!values.some((value) => value.includes("Command type name:LSI Command / Manage LSI")));
  assert.ok(!values.some((value) => value.includes("LSI command qualifier status:")));
});

test("decodes proactive command type 0x71 as CONTACTLESS STATE CHANGED", () => {
  const result = parseApduLine("D0 09 81 03 01 71 01 82 02 81 82", 14);

  assert.equal(result.kind, "payload");
  assert.equal(result.decodedFields.proactiveCommandType, "0x71 — CONTACTLESS STATE CHANGED");
  assert.equal(result.decodedFields.proactiveCommandTypeName, "CONTACTLESS STATE CHANGED");
  assert.equal(result.decodedFields.proactiveCommandTypeByte, "0x71");
  assert.equal(result.decodedFields.commandQualifierMeaning, "unknown / command-type-specific qualifier semantics unavailable");
  assert.equal(result.decodedFields.commandTypeStatus, "recognized in loaded CAT table");
});

test("uses standards-coverage wording for unknown proactive command types", () => {
  const result = parseApduLine("D0098103017A0182028182", 15);

  assert.equal(result.kind, "payload");
  assert.equal(result.decodedFields.proactiveCommandType, "0x7A — 0x7A");
  assert.equal(result.decodedFields.proactiveCommandTypeByte, "0x7A");
  assert.equal(result.decodedFields.proactiveCommandTypeName, "0x7A");
  assert.equal(result.decodedFields.commandQualifierMeaning, "unknown / command-type-specific qualifier semantics unavailable");
  assert.match(result.decodedFields.commandTypeStatus, /not present in the currently loaded standard table.*verify ETSI TS 102 223 version coverage/i);
});

test("decodes DISPLAY TEXT command qualifier semantics", () => {
  const result = parseApduLine("D009810301218182028102", 16);

  assert.equal(result.kind, "payload");
  assert.equal(result.decodedFields.proactiveCommandType, "0x21 — DISPLAY TEXT");
  assert.match(result.decodedFields.commandQualifierMeaning, /High priority, wait for user to clear message/i);
});

test("decodes OPEN CHANNEL command qualifier bitfields", () => {
  const result = parseApduLine("D009810301400782028182", 17);

  assert.equal(result.kind, "payload");
  assert.equal(result.decodedFields.proactiveCommandType, "0x40 — OPEN CHANNEL");
  assert.match(result.decodedFields.commandQualifierMeaning, /Immediate link establishment in background mode/i);
  const values = result.sections.flatMap((section) => section.fields.map((currentField) => `${currentField.label}:${currentField.value}`));
  assert.ok(values.some((value) => value.includes("Automatic reconnection:requested")));
  assert.ok(values.some((value) => value.includes("Background mode:requested")));
});

test("decodes GET INPUT and PROVIDE LOCAL INFORMATION qualifier semantics", () => {
  const getInput = parseApduLine("D009810301238782028102", 18);
  const pli = parseApduLine("D009810301260382028182", 19);

  assert.equal(getInput.decodedFields.proactiveCommandType, "0x23 — GET INPUT");
  assert.match(getInput.decodedFields.commandQualifierMeaning, /Alphabet input, UCS2 alphabet, hidden entry, unpacked format, help available/i);
  assert.equal(pli.decodedFields.proactiveCommandType, "0x26 — PROVIDE LOCAL INFORMATION");
  assert.match(pli.decodedFields.commandQualifierMeaning, /Date, time and time zone/i);
});

test("falls back to BER-TLV payload decoding when a line is not a known APDU", () => {
  const result = parseApduLine("700A8408A000000151000000", 13);

  assert.equal(result.kind, "payload");
  assert.equal(result.commandName, "BER-TLV payload");
  assert.equal(result.decodedFields.tlvItems, 1);
});

test("decodes SELECT MF response with FCP template and nested security data", () => {
  const result = parseApduLine("62 28 82 02 78 21 83 02 3F 00 A5 06 80 01 71 87 01 01 8A 01 05 AB 0B 80 01 87 A4 06 83 01 0A 95 01 08 C6 06 90 01 00 83 01 01", 14);

  assert.equal(result.kind, "payload");
  assert.equal(result.commandName, "SELECT response (FCP template)");
  assert.equal(result.decodedFields.selectResponseTemplate, "FCP template");
  assert.equal(result.decodedFields.fileIdentifier, "3F00");
  assert.equal(result.decodedFields.selectedFile, "MF");
  assert.match(result.decodedFields.fileDescriptorType, /DF or ADF/i);
  assert.equal(result.decodedFields.lifeCycleStatus, "0x05");
  assert.match(result.decodedFields.lifeCycleMeaning, /activated/i);
  assert.match(result.decodedFields.pinStateSummary, /PIN 0x01 = disabled/i);
  const values = result.sections.flatMap((currentSection) => currentSection.fields.map((currentField) => `${currentField.label}:${currentField.value}`));
  assert.ok(values.some((value) => value.includes("Proprietary information TLV:A5 06 80 01 71 87 01 01")));
  assert.ok(values.some((value) => value.includes("Security attributes TLV:AB 0B 80 01 87 A4 06 83 01 0A 95 01 08")));
  assert.ok(values.some((value) => value.includes("PIN Status Template TLV:C6 06 90 01 00 83 01 01")));
  assert.ok(values.some((value) => value.includes("PIN 0x01 state:disabled")));
});

test("decodes SELECT ISD-R response with FCI template in response APDU context", () => {
  const result = parseApduLine("6F188410A0000005591010FFFFFFFF8900000100A5049F6501FF9000", 15);

  assert.equal(result.kind, "response-apdu");
  assert.equal(result.commandName, "SELECT response (FCI template)");
  assert.match(result.layer, /GlobalPlatform|eUICC/i);
  assert.match(result.decodedFields.identifiedApplication, /ISD-R/i);
  assert.equal(result.decodedFields.selectedAid, "A0000005591010FFFFFFFF8900000100");
  assert.equal(result.decodedFields.statusWord, "9000");
});

test("decodes SELECT USIM ADF response and identifies the AID family", () => {
  const result = parseApduLine("6210820278218407A00000008710028A0105", 16);

  assert.equal(result.kind, "payload");
  assert.equal(result.commandName, "SELECT response (FCP template)");
  assert.match(result.decodedFields.identifiedApplication, /USIM/i);
  assert.equal(result.decodedFields.selectedAid, "A0000000871002");
});

test("decodes FCP templates in response APDUs and marks them as file-management responses", () => {
  const result = parseApduLine("620B8202782183023F008A01059000", 16);

  assert.equal(result.kind, "response-apdu");
  assert.equal(result.commandName, "SELECT response (FCP template)");
  assert.equal(result.decodedFields.fileIdentifier, "3F00");
  assert.equal(result.decodedFields.selectedFile, "MF");
  assert.match(result.decodedFields.fileManagementContext, /SELECT|STATUS|GET RESPONSE/i);
  assert.equal(result.decodedFields.statusWord, "9000");
});

test("decodes GlobalPlatform security-domain FCI discretionary data", () => {
  const result = parseApduLine("6F178408A000000151000000A50B730906072A864886FC6B019000", 17);

  assert.equal(result.kind, "response-apdu");
  assert.equal(result.commandName, "SELECT response (FCI template)");
  assert.match(result.decodedFields.identifiedApplication, /Security Domain|Card Manager/i);
  const values = result.sections.flatMap((currentSection) => currentSection.fields.map((currentField) => `${currentField.label}:${currentField.value}`));
  assert.ok(values.some((value) => value.includes("Security Domain Management Data:73 09 06 07 2A 86 48 86 FC 6B 01")));
  assert.ok(values.some((value) => value.includes("Object Identifier:1.2.840.114283.1")));
});

test("classifies FMD templates as structured file-management responses", () => {
  const result = parseApduLine("640783023F008A0105", 18);

  assert.equal(result.kind, "payload");
  assert.equal(result.commandName, "SELECT response (FMD template)");
  assert.equal(result.decodedFields.selectResponseTemplate, "FMD template");
  assert.equal(result.decodedFields.fileIdentifier, "3F00");
});

test("classifies malformed FCP template as SELECT response with warnings instead of crashing", () => {
  const result = parseApduLine("62108202782183023F00", 19);

  assert.equal(result.kind, "payload");
  assert.equal(result.commandName, "SELECT response (FCP template)");
  assert.ok(result.warnings.length > 0);
});

test("classifies CREATE FILE in interindustry/UICC context", () => {
  const result = parseApduLine("00 E0 00 00 02 62 00", 18);

  assert.equal(result.commandName, "CREATE FILE");
  assert.match(result.layer, /ISO 7816-4|ETSI TS 102 221/i);
});

test("classifies DEACTIVATE FILE in interindustry/UICC context", () => {
  const result = parseApduLine("00 04 00 00", 19);

  assert.equal(result.commandName, "DEACTIVATE FILE");
});

test("decodes GlobalPlatform GET STATUS entity selector", () => {
  const result = parseApduLine("80 F2 40 00 02 4F 00 00", 20);

  assert.equal(result.commandName, "GET STATUS");
  assert.match(result.decodedFields.entitySelectorMeaning, /application|applet/i);
});

test("decodes GlobalPlatform EXTERNAL AUTHENTICATE security level bits", () => {
  const result = parseApduLine("84 82 03 00 08 01 02 03 04 05 06 07 08", 21);

  assert.equal(result.commandName, "EXTERNAL AUTHENTICATE");
  assert.match(result.decodedFields.securityLevelMeaning, /C-MAC/i);
  assert.match(result.decodedFields.securityLevelMeaning, /C-DECRYPTION/i);
});

test("decodes MANAGE LSI configure command with SGP.22 additional TLVs", () => {
  const result = parseApduLine("80 7C 04 00 0D 80 01 02 81 01 01 90 02 01 03 91 01 02 00", 22);

  assert.equal(result.commandName, "MANAGE LSI");
  assert.match(result.decodedFields.operation, /configure lsis/i);
  assert.equal(result.decodedFields.highestProposedLsi, 2);
  assert.match(result.decodedFields.lsiOptionsMeaning, /NAD/i);
  assert.match(result.decodedFields.deviceMepModes, /MEP-A1/i);
  assert.match(result.decodedFields.deviceMepModes, /MEP-B/i);
  assert.equal(result.decodedFields.maxEnabledProfileLsis, 2);
});

test("explains non-canonical MANAGE LSI select-lsi-with-Le cases against reset-LSE semantics", () => {
  const result = parseApduLine("80 7C 00 00 00", 23);

  assert.equal(result.commandName, "MANAGE LSI");
  assert.match(result.decodedFields.operation, /Select LSI/i);
  assert.ok(result.warnings.some((message) => /Reset LSE/i.test(message)));
  const sectionValues = result.sections.flatMap((currentSection) => currentSection.fields.map((currentField) => `${currentField.label}:${currentField.value}`));
  assert.ok(sectionValues.some((value) => /Reset comparison:ETSI TS 102 221 defines Reset LSE as P1=0x01/i.test(value)));
});

test("decodes MANAGE LSI configure response data with SGP.22 TLVs", () => {
  const result = parseApduLine("80010281010190030101039101029000", 24);

  assert.equal(result.kind, "response-apdu");
  assert.equal(result.commandName, "MANAGE LSI response");
  assert.equal(result.decodedFields.manageLsiResponseType, "Configure LSIs response");
  assert.equal(result.decodedFields.highestSupportedLsi, 2);
  assert.match(result.decodedFields.jointlySupportedMepMode, /MEP-A1/i);
  assert.match(result.decodedFields.euiccSupportedMepModes, /MEP-B/i);
  assert.equal(result.decodedFields.jointlySupportedEnabledProfileLsis, 2);
  assert.equal(result.decodedFields.statusWord, "9000");
});

test("decodes ETSI TS 102 221 TERMINAL CAPABILITY with A9 template payload", () => {
  const result = parseApduLine("80 AA 00 00 0F A9 0D 80 03 07 4B 32 81 00 82 01 01 83 01 03", 25);

  assert.equal(result.commandName, "TERMINAL CAPABILITY");
  assert.equal(result.layer, "ETSI TS 102 221 UICC layer");
  assert.match(result.decodedFields.terminalVoltageClass, /Class A/i);
  assert.match(result.decodedFields.terminalVoltageClass, /Class C/i);
  assert.equal(result.decodedFields.terminalMaxPower, "75 mA");
  assert.equal(result.decodedFields.terminalClockFrequency, "5.0 MHz");
  assert.match(result.decodedFields.euiccCapabilities, /Local profile management/i);
  assert.match(result.decodedFields.euiccCapabilities, /Profile download/i);
});

test("recognizes ES10 ASN.1 response payloads without misclassifying them as proactive commands", () => {
  const result = parseApduLine("BF22009000", 26);

  assert.equal(result.kind, "response-apdu");
  assert.equal(result.commandName, "ES10 / eUICC ASN.1 payload");
  assert.equal(result.decodedFields.statusWord, "9000");
  assert.match(result.decodedFields.firstEs10Tag, /BF22/i);
  assert.doesNotMatch(result.shortMeaning, /proactive/i);
});

test("surfaces ES10 ASN.1 hints inside GlobalPlatform STORE DATA payloads", () => {
  const result = parseApduLine("80 E2 00 00 03 BF 22 00", 27);

  assert.equal(result.commandName, "STORE DATA");
  assert.match(result.decodedFields.es10Hint, /BF22/i);
});

test("treats chunked ES10 STORE DATA first block as partial top-level ASN.1 object", () => {
  const result = parseApduLine(
    "81 E2 11 00 FF BF 38 82 02 F0 30 49 80 10 DC CD 23 50 EC 13 75 E1 F6 23 E0 B8 50 B3 02 EC 81 10 A7 E9 C1 34 14 F4 A8 AE FC 37 03 76 E2 81 6E D1 83 11 73 6D 64 70 70 6C 75 73 2E 74 65 73 74 2E 63 6F 6D 84 10 56 E3 54 DF 94 81 56 DF 18 E2 5D D3 39 45 D9 B3 5F 37 40 F0 DE B4 FB 99 D3 3D 4A 62 00 CF A7 6E 35 87 B4 18 29 97 35 6E E5 1D 78 88 CE 4B 05 48 8D 8B 62 4B 7B 60 84 E3 B2 9C 81 F9 33 C2 E2 B3 47 A7 E7 C3 ED 19 28 E1 F5 AA 58 AB C3 B7 87 F7 3B BA E3 04 14 F5 41 72 BD F9 8A 95 D6 5C BE B8 8A 38 A1 C1 1D 80 0A 85 C3 30 82 02 37 30 82 01 DD A0 03 02 01 02 02 01 64 30 0A 06 08 2A 86 48 CE 3D 04 03 02 30 49 31 15 30 13 06 03 55 04 03 0C 0C 47 53 4D 41 20 54 65 73 74 20 43 49 31 11 30 0F 06 03 55 04 0B 0C 08 54 45 53 54 43 45 52 54 31 10 30 0E 06 03 55 04 0A 0C 07 52 53 50",
    28,
  );

  assert.equal(result.commandName, "STORE DATA");
  assert.match(result.decodedFields.firstEs10Tag || result.decodedFields.es10Hint, /BF38/i);
  assert.equal(result.decodedFields.storeDataChunkRole, "Initial chunk");
  assert.match(result.decodedFields.es10ChunkState, /continues in later chunks/i);
});

test("treats later STORE DATA blocks as continuation chunks instead of malformed standalone TLV objects", () => {
  const result = parseApduLine(
    "81 E2 11 01 FF 54 45 53 54 31 0B 30 09 06 03 55 04 06 13 02 49 54 30 1E 17 0D 31 37 30 32 30 31 31 33 33 38 35 36 5A 17 0D 32 30 30 32 30 31 31 33 33 38 35 36 5A 30 25 31 0D 30 0B 06 03 55 04 0A 0C 04 41 43 4D 45 31 14 30 12 06 03 55 04 03 0C 0B 54 45 53 54 20 53 4D 2D 44 50 2B 30 59 30 13 06 07 2A 86 48 CE 3D 02 01 06 08 2A 86 48 CE 3D 03 01 07 03 42 00 04 4D FE D4 F4 69 47 91 BF 16 95 CE A0 30 7A 35 B4 18 01 96 95 38 7B B7 5B 7D 24 47 B6 B5 20 9F 04 45 AE 4E 5E 52 1C D1 38 88 D7 5F E0 7C 85 80 22 2A E2 0D BA AC 1D 77 CD 76 30 49 93 42 1B D7 39 A3 81 D9 30 81 D6 30 1F 06 03 55 1D 23 04 18 30 16 80 14 F5 41 72 BD F9 8A 95 D6 5C BE B8 8A 38 A1 C1 1D 80 0A 85 C3 30 1D 06 03 55 1D 0E 04 16 04 14 BD 5A 82 CC 1A 96 60 21 18 BA 75 60 A1 FF 83 A7 8B 21 0B E5 30 0E 06 03 55 1D",
    29,
  );

  assert.equal(result.commandName, "STORE DATA");
  assert.match(result.decodedFields.storeDataChunkRole, /Chunk #1|Continuation block #1/i);
  assert.match(result.decodedFields.es10ChunkState, /Continuation fragment/i);
  assert.ok(!result.warnings.some((message) => /TLV parse stopped at offset/i.test(message)));
});

test("decodes retry-counter style status words", () => {
  const result = parseApduLine("63C3", 30);

  assert.equal(result.kind, "response-apdu");
  assert.equal(result.decodedFields.statusWord, "63C3");
  assert.match(result.decodedFields.statusMeaning, /3 retry/i);
});

test("decodes GlobalPlatform INSTALL parameter tags more deeply", () => {
  const result = parseApduLine(
    "80 E6 04 00 20 08 A0 00 00 00 03 00 00 00 00 08 A0 00 00 00 03 00 00 01 01 80 09 C9 02 01 02 EF 03 C7 01 10 00",
    31,
  );

  assert.equal(result.commandName, "INSTALL");
  assert.match(result.decodedFields.installSubtype, /for install/i);
  assert.match(result.decodedFields.privileges, /Security Domain/i);
  assert.match(result.decodedFields.installParameterSummary, /Application Specific Parameters/i);
  assert.match(result.decodedFields.installParameterSummary, /Volatile data space limit/i);
});

test("decodes GlobalPlatform INITIALIZE UPDATE response data", () => {
  const result = parseApduLine("000102030405060708090102151234A1A2A3A4A5A601020304050607089000", 32);

  assert.equal(result.kind, "response-apdu");
  assert.equal(result.commandName, "INITIALIZE UPDATE response");
  assert.equal(result.decodedFields.scpIdentifier, "SCP02");
  assert.equal(result.decodedFields.keyVersionNumber, 1);
  assert.equal(result.decodedFields.sequenceCounter, "1234");
  assert.equal(result.decodedFields.statusWord, "9000");
});

test("decodes GlobalPlatform registry-style BER-TLV responses", () => {
  const result = parseApduLine("E30D4F04A00000019F700107C501809000", 33);

  assert.equal(result.kind, "response-apdu");
  assert.equal(result.commandName, "GlobalPlatform registry response");
  assert.equal(result.decodedFields.registryEntries, 1);
  assert.equal(result.decodedFields.firstEntryAid, "A0000001");
  assert.match(result.decodedFields.firstEntryPrivileges, /Security Domain/i);
});
