# Missing Coverage Report

Coverage review completed before implementing the next decoder pass. This review compares the current analyzer against ISO/IEC 7816-4, ETSI TS 102 221, ETSI TS 102 223, GlobalPlatform Card Specification, public GSMA eUICC usage, and Wireshark SIM/CAT dissectors.

## 1. Currently supported

- Command APDU structure parsing:
  - `CLA`, `INS`, `P1`, `P2`, `Lc`, `Data`, `Le`
  - APDU case recognition, including extended length
- ISO/ETSI/GP command detection:
  - `SELECT FILE`, `STATUS`, `READ/UPDATE BINARY`, `READ/UPDATE/SEARCH RECORD`
  - PIN commands, `AUTHENTICATE`, `GET RESPONSE`, `GET/PUT DATA`, `MANAGE CHANNEL`
  - CAT/USAT commands: `TERMINAL PROFILE`, `ENVELOPE`, `FETCH`, `TERMINAL RESPONSE`
  - `MANAGE LSI`, `TERMINAL CAPABILITY`
  - GlobalPlatform: `INSTALL`, `LOAD`, `DELETE`, `PUT KEY`, `INITIALIZE UPDATE`, `EXTERNAL AUTHENTICATE`, `GET STATUS`, `STORE DATA`, `SET STATUS`
- Response APDU support:
  - status word splitting and common SW decoding
  - proactive command template decoding from `FETCH` responses
  - GlobalPlatform registry and `INITIALIZE UPDATE` response decoding
  - ES10 ASN.1 top-level tag recognition

## 2. Missing or weak coverage before this pass

| Area | What is missing | Confirmed by | Priority | Tests to add |
| --- | --- | --- | --- | --- |
| `SELECT` response data | `62`/`6F`/`64` payloads are only treated as generic BER-TLV, not as FCP/FCI/FMD | ISO/IEC 7816-4 SELECT response templates; ETSI TS 102 221 FCP clauses; Wireshark GSM SIM dissector | High | MF FCP, USIM ADF FCI, ISD-R FCI |
| FCP tag naming | No dedicated decoding for `82`, `83`, `84`, `8A`, `80`, `81`, `88`, `A5`, `AB`, `C6` | ETSI TS 102 221 clauses 11.1.1.4.x; Wireshark SIM dissector | High | Dedicated tag regression tests |
| File descriptor semantics | No explanation of DF/ADF vs EF, shareable bit, record structure, record length | ETSI TS 102 221 table 11.5; Mozilla/B2G UICC FCP decoder references | High | FCP examples with `78 21`, `42 21`, `01 21` |
| Selected file naming | No mapping from file IDs / AIDs to MF, EF_DIR, ICCID, USIM, ISIM, ISD-R, ECASD | ETSI TS 102 221 common file IDs; public eUICC AID references; GP select behavior | High | `3F00`, `2F00`, `2FE2`, USIM AID, ISD-R AID |
| PIN status template | `C6` not decoded into `90`, `95`, `83` semantic structure | ETSI TS 102 221 PIN status template DO | High | FCP sample with `C6` |
| Proprietary/security nested templates | `A5` / `AB` nested tags not explained | ETSI TS 102 221 proprietary information and security attribute DOs | High | MF FCP example using `A5`, `AB` |
| GlobalPlatform select response | No dedicated FCI interpretation for selected security domains (`84`, `A5`, `73`, `9F65`, `9F6E`) | GlobalPlatform select response tables | High | ISD-R / Security Domain FCI sample |
| Malformed select response handling | Known template with broken lengths should stay classified as SELECT response, with warning | ISO/ETSI BER-TLV structure; Wireshark defensive dissector behavior | Medium | malformed `62 ...` sample |
| STATUS response side | `STATUS`/`GET RESPONSE` file management templates still mostly generic | ISO/IEC 7816-4 and ETSI TS 102 221 | Medium | `STATUS` sample responses |
| Deeper ES10 semantic decoding | Current ES10 layer identifies top-level tags but not full nested semantics | SGP.22/23 ASN.1 payload structure | Medium | already partially covered; deeper tests later |

## 3. Standards / dissectors confirming the gaps

- ISO/IEC 7816-4:
  - top-level response templates `62` FCP, `6F` FCI, `64` FMD
- ETSI TS 102 221:
  - FCP structure for MF/DF/ADF/EF
  - file descriptor (`82`)
  - file identifier (`83`)
  - DF name / AID (`84`)
  - proprietary information (`A5`)
  - security attributes (`AB`)
  - short file identifier (`88`)
  - life cycle status integer (`8A`)
  - PIN status template DO (`C6`)
- GlobalPlatform:
  - SELECT response FCI for security domains and Card Manager
  - common SD/ISD proprietary tags such as `73`, `9F65`, `9F6E`
- Wireshark references:
  - `packet-gsm_sim.c`
  - `packet-etsi_card_app_toolkit.c`

## 4. Priority implementation order

1. Add dedicated SELECT response classifier for `62` / `6F` / `64`
2. Decode high-signal FCP/FCI/FMD tags and nested templates
3. Add file ID / AID naming for MF, common EFs, USIM/ISIM, ISD-R, ECASD
4. Add GlobalPlatform / eUICC FCI classification for security domain selection
5. Add malformed SELECT response warnings and tests

## 5. Test examples to add

- SELECT MF response with FCP:
  - `62 28 82 02 78 21 83 02 3F 00 ...`
- SELECT ISD-R response with FCI:
  - FCI template containing `84` with ISD-R AID and nested `A5`/`73`
- SELECT USIM ADF response:
  - FCI/FCP with USIM AID prefix `A0000000871002`
- Generic BER-TLV payload that starts with another template and must remain generic
- Malformed `62` / `6F` template with truncated length
