# UICC APDU Analyzer

Layered APDU analyzer for UICC / eSIM / telecom smartcard logs with contextual decoding across ISO 7816-4, ETSI TS 102 221, ETSI TS 102 223, ETSI TS 102 226, 3GPP TS 31.111, and GlobalPlatform card-management traffic.

## Scope

This project is intentionally built as a protocol-analysis tool rather than a flat `INS -> name` lookup table.

It currently focuses on command APDUs and provides:

- ISO 7816-4 command APDU parsing
- ISO 7816-4 response APDU parsing with status word separation
- short and extended APDU case handling
- structural validation and malformed APDU warnings
- contextual command matching by `CLA`, `INS`, and spec-layer expectations
- command-specific decoding for common UICC, CAT/USAT, ETSI remote-management, and GlobalPlatform commands
- proactive command BER-TLV decoding in FETCH response payloads and standalone proactive templates
- `MANAGE LSI` command and response decoding, including `SGP.22` `90` / `91` MEP-related TLVs when visible
- deeper GlobalPlatform decoding for `INSTALL` parameters, `INITIALIZE UPDATE` response data, and registry-style response payloads
- expandable browser UI with filters, search, and warning emphasis

## Supported protocol layers

### 1. ISO 7816-4 APDU layer

- `SELECT FILE`
- `STATUS`
- `READ BINARY`
- `UPDATE BINARY`
- `READ RECORD`
- `UPDATE RECORD`
- `SEARCH RECORD`
- `VERIFY PIN`
- `CHANGE PIN`
- `DISABLE PIN`
- `ENABLE PIN`
- `UNBLOCK PIN`
- `INCREASE`
- `AUTHENTICATE`
- `GET RESPONSE`
- `GET DATA`
- `PUT DATA`
- `MANAGE CHANNEL`

### 2. ETSI TS 102 221 UICC layer

- UICC-oriented `STATUS`
- UICC-oriented `AUTHENTICATE`
- `MANAGE LSI`

### 3. ETSI TS 102 223 / 3GPP TS 31.111 CAT/USAT layer

- `TERMINAL PROFILE`
- `ENVELOPE`
- `FETCH`
- `TERMINAL RESPONSE`

The CAT layer also decodes common proactive command types carried inside CAT TLVs, including:

- `REFRESH`
- `OPEN CHANNEL`
- `CLOSE CHANNEL`
- `RECEIVE DATA`
- `SEND DATA`

### 4. ETSI TS 102 226 RFM/RAM layer

- `STORE DATA`

### 5. GlobalPlatform card management layer

- `INSTALL`
- `LOAD`
- `DELETE`
- `PUT KEY`
- `INITIALIZE UPDATE`
- `EXTERNAL AUTHENTICATE`
- `GET STATUS`
- `STORE DATA`
- `SET STATUS`

## Architecture

The codebase is organized into reusable layers instead of a single monolithic parser:

- [src/iso7816/apdu-structure.js](C:/Users/junli/Documents/apdus/src/iso7816/apdu-structure.js)
  Parses APDU structure and validates case/lc/le consistency.
- [src/layers/index.js](C:/Users/junli/Documents/apdus/src/layers/index.js)
  Aggregates all protocol-layer command definitions and resolves the best contextual match.
- [src/layers/iso7816/commands.js](C:/Users/junli/Documents/apdus/src/layers/iso7816/commands.js)
  Core interindustry command decoders.
- [src/layers/etsi102221/commands.js](C:/Users/junli/Documents/apdus/src/layers/etsi102221/commands.js)
  UICC-specific command decoders.
- [src/layers/etsi102223/commands.js](C:/Users/junli/Documents/apdus/src/layers/etsi102223/commands.js)
  CAT / USAT command and TLV decoders.
- [src/layers/etsi102226/commands.js](C:/Users/junli/Documents/apdus/src/layers/etsi102226/commands.js)
  Remote-management store-data handling.
- [src/layers/globalplatform/commands.js](C:/Users/junli/Documents/apdus/src/layers/globalplatform/commands.js)
  GlobalPlatform management command decoders.
- [src/core/tlv.js](C:/Users/junli/Documents/apdus/src/core/tlv.js)
  Shared BER-TLV and CAT TLV parsers.
- [src/apdu-parser.js](C:/Users/junli/Documents/apdus/src/apdu-parser.js)
  End-to-end per-line analysis pipeline.

## APDU parsing behavior

The analyzer supports:

- Case 1 APDU
- Case 2 short and extended APDU
- Case 3 short and extended APDU
- Case 4 short and extended APDU
- response APDU parsing with `data || SW1 SW2` splitting

It decodes:

- `CLA`
- `INS`
- `P1`
- `P2`
- `Lc`
- `Data`
- `Le`
- response data
- `SW1` / `SW2`

It also validates:

- minimum header length
- short-vs-extended body structure
- `Lc` versus available data bytes
- extra trailing bytes beyond the declared structure
- malformed TLV payloads in supported command families

## Response and payload classification

Each input line is now classified as one of:

- command APDU
- response APDU
- standalone proactive command template
- generic BER-TLV payload
- unknown / proprietary payload

Common status words such as `9000`, `91xx`, `61xx`, `6F00`, `6985`, `6A82`, `6A88`, `6D00`, and `6E00` are separated from response data and explained.

If response data begins with `D0`, the analyzer treats it as a proactive command BER-TLV template and decodes common CAT/USAT TLVs including:

- Command Details
- Device Identities
- Result
- Duration
- Alpha Identifier
- Address
- Text String
- Item
- File List
- Channel Data
- Bearer Description

If response data matches `MANAGE LSI` response structures, the analyzer also decodes:

- `configure LSIs` response TLVs from ETSI TS 102 221
- `SGP.22` `90` / `91` additional TLVs for MEP mode negotiation and enabled-profile LSI limits
- `retrieve SWP` response payloads
- ATR-carrying responses from `reset LSE` / `assign SWP`

If response data matches common GlobalPlatform structures, the analyzer also decodes:

- `INITIALIZE UPDATE` response data
  - key diversification data
  - key version number
  - SCP identifier
  - SCP i-parameter
  - sequence counter when present
  - card challenge
  - card cryptogram
- registry-style BER-TLV responses such as `GET STATUS`
  - registry entry template
  - AID
  - lifecycle-state bytes
  - privilege bytes

## UI

The web UI is meant to feel closer to a protocol-analysis workspace than a form demo:

- expandable result cards
- command/category/layer filters
- unknown-only and warnings-only filters
- full-text search across decoded content
- structured decoded sections
- warning severity badges
- better separation of raw bytes versus interpreted fields

## References used

This implementation was guided by public standards and public implementation references, especially:

- [ISO/IEC 7816-4 summary references and command structure discussions](https://cardwerk.com/smart-card-standard-iso7816-4-section-6-basic-interindustry-commands/)
- [ETSI TS 102 221](https://www.etsi.org/deliver/etsi_ts/102200_102299/102221/11.01.00_60/ts_102221v110100p.pdf)
- [ETSI TS 102 223](https://www.etsi.org/deliver/etsi_ts/102200_102299/102223/11.02.00_60/ts_102223v110200p.pdf)
- [ETSI TS 102 226](https://www.etsi.org/deliver/etsi_ts/102200_102299/102226/08.03.00_60/ts_102226v080300p.pdf)
- [3GPP TS 31.111](https://www.etsi.org/deliver/etsi_ts/131100_131199/131111/03.08.00_60/ts_131111v030800p.pdf)
- [GlobalPlatform Card Specification v2.3](https://globalplatform.org/wp-content/uploads/2018/03/GPC_Specification_v2.3.pdf)
- [3GPP TS 31.111 overview pages for proactive command structure](https://www.tech-invite.com/3m31/toc/tinv-3gpp-31-111_e.html)
- [Wireshark ETSI CAT dissector tree](https://gitlab.com/wireshark/wireshark/-/tree/master/epan/dissectors)

These were used as design references, not copied verbatim into the code.

## Current limitations

- Some command payloads are still decoded structurally rather than semantically complete. This is most visible for:
  - terminal profile capability bytes
  - secure channel cryptograms
  - parts of GlobalPlatform `PUT KEY`, `LOAD`, and delegated-management receipts
  - some vendor-specific `MANAGE LSI` extensions beyond ETSI TS 102 221 and public `SGP.22` additions
- Response APDUs are now supported, but command/response correlation is not yet stateful. The analyzer does not yet remember the previous `FETCH` command or pair APDU exchanges across multiple lines.
- The line parser prefers clearly APDU-looking byte runs. Extremely noisy mixed logs may still need preprocessing.
- CAT proactive command type inference is available only when the command details TLV is visible in the command payload.

## Run

Tests:

```powershell
node --test
```

Local UI:

```powershell
node scripts/serve.mjs
```

Then open [http://localhost:4173](http://localhost:4173).

## How to extend

To add a new command cleanly:

1. Choose the correct layer module under [src/layers](C:/Users/junli/Documents/apdus/src/layers).
2. Add a command definition with:
   - `id`
   - `name`
   - `layer`
   - `category`
   - `specArea`
   - `summary`
   - `match(apdu)`
   - `decode(apdu)`
3. Reuse shared helpers from [src/core](C:/Users/junli/Documents/apdus/src/core) and [src/layers/shared.js](C:/Users/junli/Documents/apdus/src/layers/shared.js).
4. Add tests under [tests](C:/Users/junli/Documents/apdus/tests).
5. Run `node --test`.

The intended model is “layered contextual analyzers with reusable payload parsers”, not “one bigger lookup table”.
