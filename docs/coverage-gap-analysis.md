# Coverage Gap Analysis

Date: 2026-05-23

## Reference repos reviewed

- Wireshark ETSI CAT dissector
  - [packet-etsi_card_app_toolkit.c](https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-etsi_card_app_toolkit.c)
- GlobalPlatform / gpshell
  - [kaoh/globalplatform](https://github.com/kaoh/globalplatform)
  - [GlobalPlatform C library docs](https://kaoh.github.io/globalplatform/globalPlatformSpecification.html)
- Onomondo UICC
  - [onomondo/onomondo-uicc](https://github.com/onomondo/onomondo-uicc)
- mitshell/card
  - [mitshell/card](https://github.com/mitshell/card)

These were used as behavioral references for missing command families, TLV semantics, and management-command coverage. The implementation here remains original and registry-driven.

## What was missing before this pass

### CAT / USAT

- Response-side proactive command decoding existed, but coverage was still narrow.
- Terminal Profile existed as raw bytes only, with no capability interpretation.
- Some TLVs were decoded structurally but not presented clearly enough for analysts.
- `Result`, `Device Identities`, and `Duration` were not explicit enough about full TLV bytes versus value bytes.

### ISO / ETSI UICC

- Administrative file commands from ISO/ETSI file-management flows were not recognized:
  - `CREATE FILE`
  - `DELETE FILE`
  - `DEACTIVATE FILE`
  - `ACTIVATE FILE`

### GlobalPlatform

- `GET STATUS` lacked entity-selector semantics.
- `EXTERNAL AUTHENTICATE` lacked security-level interpretation.
- `INITIALIZE UPDATE` lacked an SCP-style host-challenge hint.
- `INSTALL` decoding needed a little more structure around subtype/P2 semantics.

## Implemented in this pass

### CAT / USAT improvements

- Improved `TERMINAL PROFILE` with initial capability-bit decoding.
  - Current mapped hints include:
    - Profile download
    - SMS-PP data download
    - Cell Broadcast data download
    - Menu selection
    - Timer expiration
    - Command result
    - Call control by NAA
    - Cell identity status
    - Display Text
    - Get Inkey
    - Get Input
    - Play Tone
- Improved CAT TLV presentation:
  - now shows full TLV bytes, not only value bytes
  - example style:
    - `Result TLV = 83 01 00`
    - `Result value = 00`
    - `General result = 0x00`
    - `Meaning = Command performed successfully`
- Added clearer direction semantics for `Device Identities`
  - `Message direction = UICC -> Terminal` or `Terminal -> UICC`
- Added mapped result meanings for common `Result` values.

### ISO / ETSI UICC command coverage

- Added:
  - `CREATE FILE`
  - `DELETE FILE`
  - `DEACTIVATE FILE`
  - `ACTIVATE FILE`

These are recognized only in interindustry/UICC-style command context, so they do not override proprietary GlobalPlatform management APDUs using overlapping INS values.

### GlobalPlatform improvements

- `GET STATUS`
  - now maps common `P1` entity selectors such as:
    - Issuer Security Domain
    - Application / applet instances
    - Executable Load Files
    - Executable Load File modules
- `EXTERNAL AUTHENTICATE`
  - now decodes common SCP security-level bits:
    - C-MAC
    - C-DECRYPTION
    - R-MAC
    - R-ENCRYPTION
- `INITIALIZE UPDATE`
  - now flags common 8-byte host-challenge size as a likely SCP02/SCP03-style setup flow
- `INSTALL`
  - now includes explicit subtype and a clearer P2 interpretation field
  - now decodes common install-parameter tags including:
    - `C9` Application Specific Parameters
    - `EF` System Specific Parameters
    - `C6` non volatile code space limit
    - `C7` volatile data space limit
    - `C8` non volatile data space limit
    - `CF` implicit selection parameters
    - `5F20` provider identifier
- response-side GlobalPlatform decoding now recognizes:
  - `INITIALIZE UPDATE` responses for `SCP02` and common `SCP03` layouts
  - registry-style BER-TLV payloads such as `GET STATUS` response entries with `E3`, `4F`, `9F70`, and `C5`

## Remaining high-value gaps

### CAT / USAT

- More complete `TERMINAL PROFILE` bit coverage across later bytes
- More proactive-command-specific decoding:
  - `REFRESH` qualifier details
  - `OPEN CHANNEL` bearer/address/buffer-size relationships
  - `SET UP MENU` / `SELECT ITEM`
  - `DISPLAY TEXT` DCS-specific text decoding
- More detailed `Result` code table coverage

### Response APDU correlation

- The analyzer still does not correlate a `91xx` status with the next `FETCH`
- It does not yet maintain multi-line transaction context for:
  - command + response pairs
  - chained `STORE DATA` / `LOAD`
  - secure channel setup state

### GlobalPlatform

- Better SCP-specific interpretation for:
  - `EXTERNAL AUTHENTICATE` session mode
  - command/response secure-messaging envelopes
- Better `LOAD` block-chain interpretation
- More complete `GET STATUS` response semantics
  - exact lifecycle-state names by entity type
  - more registry tags beyond `4F`, `9F70`, and `C5`
- Deeper delegated-management receipt and token decoding

### UICC file-system behavior

- No stateful selected-file tracking yet
- No FCP/FCI response parser yet
- No read/write access-control explanation from ARR/FCP content yet

### MANAGE LSI / eUICC port management

- `MANAGE LSI` now covers ETSI TS 102 221 command and response structures plus public `SGP.22` `90` / `91` TLVs.
- Remaining gaps are mostly:
  - transaction correlation between a specific `MANAGE LSI` command and its following response APDU
  - richer decoding of ATR content returned by `reset LSE` / `assign SWP`
  - any private/vendor TLVs beyond the public `ETSI` and `SGP.22` definitions

## Suggested next steps

1. Add response APDU transaction pairing
2. Add deeper `TERMINAL PROFILE` capability-table coverage
3. Add proactive-command-specific decoding for `REFRESH`, `OPEN CHANNEL`, `DISPLAY TEXT`, `SET UP MENU`
4. Add FCP / FCI BER-TLV response parsing for `SELECT` / `STATUS`
5. Add richer GlobalPlatform `INSTALL` parameter-tag decoding and SCP response handling
