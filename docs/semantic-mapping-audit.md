# Semantic Mapping Audit

This report tracks semantic mappings that the analyzer turns from raw bytes into human-readable meaning.

Priority policy:
- `confirmed`: mapping is backed by an identified standard clause, public implementation, or both
- `uncertain`: mapping is plausible or partially implemented, but not yet fully validated
- `unknown`: decoder should avoid inventing semantics and fall back to raw structure

## High-priority audit

| Mapping name | Current decoded value | Expected value | Source | Confidence | Test added |
| --- | --- | --- | --- | --- | --- |
| REFRESH qualifier `0x00` | NAA Initialization and Full File Change Notification | Same | ETSI TS 102 223 command details for REFRESH; Wireshark `packet-etsi_card_app_toolkit.c` refresh qualifier table | confirmed | yes |
| REFRESH qualifier `0x01` | File Change Notification | Same | ETSI TS 102 223; Wireshark `packet-etsi_card_app_toolkit.c` | confirmed | yes |
| REFRESH qualifier `0x02` | NAA Initialization and File Change Notification | Same | ETSI TS 102 223; Wireshark `packet-etsi_card_app_toolkit.c` | confirmed | yes |
| REFRESH qualifier `0x03` | NAA Initialization | Same | ETSI TS 102 223; Wireshark `packet-etsi_card_app_toolkit.c` | confirmed | yes |
| REFRESH qualifier `0x04` | UICC Reset | Same | ETSI TS 102 223; Wireshark `packet-etsi_card_app_toolkit.c` | confirmed | yes |
| REFRESH qualifier `0x05` | NAA Application Reset | Same | ETSI TS 102 223; Wireshark `packet-etsi_card_app_toolkit.c` | confirmed | yes |
| REFRESH qualifier `0x06` | NAA Session Reset | Same | ETSI TS 102 223; Wireshark `packet-etsi_card_app_toolkit.c` | confirmed | yes |
| REFRESH qualifier `0x07` | Steering of Roaming | Same | ETSI TS 102 223; Wireshark `packet-etsi_card_app_toolkit.c` | confirmed | yes |
| REFRESH qualifier `0x08` | Steering of Roaming for I-WLAN | Same | ETSI TS 102 223; Wireshark `packet-etsi_card_app_toolkit.c` | confirmed | yes |
| REFRESH qualifier `0x09` | eUICC Profile State Change | Same | ETSI TS 102 223 release 14+ REFRESH qualifier table; Wireshark `packet-etsi_card_app_toolkit.c` | confirmed | yes |
| REFRESH qualifier `0x0A` | Application Update | Same | ETSI TS 102 223 release 14+ REFRESH qualifier table; Wireshark `packet-etsi_card_app_toolkit.c` | confirmed | yes |
| Device identities `81/82/83` | `UICC` / `Terminal` / `Network` | Same | ETSI TS 102 223 device identities coding; Wireshark `packet-etsi_card_app_toolkit.c` | confirmed | covered by existing proactive/FETCH tests |
| Result TLV general result `0x00..0x39` subset | Existing textual result labels | Same for currently implemented subset | ETSI TS 102 223 / 3GPP TS 31.111 result code tables; Wireshark `packet-etsi_card_app_toolkit.c` | confirmed | covered by existing TERMINAL RESPONSE tests |
| SELECT response top-level templates `62/64/6F` | `FCP template` / `FMD template` / `FCI template` | Same | ISO/IEC 7816-4 file selection response templates; Wireshark `packet-gsm_sim.c` | confirmed | yes |
| SELECT response tag `82` | File Descriptor | Same | ISO/IEC 7816-4 + ETSI TS 102 221 | confirmed | yes |
| SELECT response tag `83` | File Identifier | Same | ISO/IEC 7816-4 + ETSI TS 102 221 | confirmed | yes |
| SELECT response tag `84` | DF Name / AID | Same | ISO/IEC 7816-4 + ETSI TS 102 221 | confirmed | yes |
| SELECT response tag `8A` | Life Cycle Status Integer | Same | ISO/IEC 7816-4 + ETSI TS 102 221 | confirmed | yes |
| SELECT response tag `A5` | Proprietary information | Same | ISO/IEC 7816-4 / GlobalPlatform FCI | confirmed | yes |
| SELECT response tag `AB` | Security attributes | Same | ETSI TS 102 221 | confirmed | yes |
| SELECT response tag `C6` | PIN Status Template DO | Same | ETSI TS 102 221 | confirmed | yes |
| PIN state bitmap `PS_DO` bit handling | `1 = enabled`, `0 = disabled` | Same | ETSI TS 102 221 PIN Status Template DO rules | confirmed | yes |
| Common FID names `3F00`, `2F00`, `2FE2`, `6F07`, `6F46`, `6FAD` | Existing mapped names | Same | ETSI TS 102 221 / 3GPP file system conventions | confirmed | partially covered |
| AID prefixes for USIM / ISIM / ISD-R / ECASD / Card Manager | Existing mapped names | Same for current subset | 3GPP USIM/ISIM AIDs, GSMA eUICC AIDs, GlobalPlatform Security Domain AIDs | confirmed | yes |
| ES10 top-level tags `BF20..BF43` subset | Existing mapped object names | Same for current subset | GSMA SGP.22 / SGP.23 tag space, plus public eUICC client implementations | confirmed | yes |
| ISO status words `9000`, `61xx`, `62xx`, `63Cx`, `67 00`, `68 81/82`, `69xx`, `6Axx`, `6D00`, `6E00`, `6F00`, `9300` | Existing text meanings | Same for current subset | ISO/IEC 7816-4 with UICC/CAT additions | confirmed | yes |

## Mappings that remain uncertain or intentionally conservative

| Mapping name | Current decoded value | Expected value | Source | Confidence | Test added |
| --- | --- | --- | --- | --- | --- |
| OPEN CHANNEL qualifier bit semantics beyond bits `1..4` | RFU warning only | Needs bearer-specific validation before extending | ETSI TS 102 223 OPEN CHANNEL qualifier tables; Wireshark comparison still incomplete | uncertain | yes for current confirmed subset |
| CLOSE CHANNEL qualifier bit `1` | Shown as possible mode-specific hint | Context-dependent between packet-data reuse and UICC server mode | ETSI TS 102 223 release-dependent wording; Wireshark comparison still incomplete | uncertain | no |
| SEND DATA / RECEIVE DATA qualifier semantics beyond current bit subset | Minimal semantics + RFU warning | Needs full standards table audit | ETSI TS 102 223 | uncertain | partial |
| DISPLAY TEXT / GET INPUT / GET INKEY semantic labels | Current implementation kept, but not fully re-audited clause-by-clause yet | Needs clause-level table validation | ETSI TS 102 223; Wireshark comparison pending | uncertain | yes, but audit still incomplete |
| TERMINAL PROFILE capability bit naming | Current capability hints | Needs bit-by-bit audit against standard tables | ETSI TS 102 223 terminal profile tables; Wireshark `packet-etsi_card_app_toolkit.c` | uncertain | partial |
| TERMINAL CAPABILITY A9 nested objects | Current curated decoding | Needs full object-table audit | ETSI TS 102 221 terminal capability encoding | uncertain | partial |
| SELECT proprietary nested tags beyond current subset | Current mix of named tags and raw TLV fallback | Needs deeper clause-by-clause tag audit | ETSI TS 102 221 / GlobalPlatform / Wireshark | uncertain | partial |
| GlobalPlatform INSTALL parameter tags beyond current subset | Current curated subset only | Unknown tags should remain raw until validated | GlobalPlatform Card Specification | uncertain | partial |

## Practical decoder rule

When a semantic mapping is not confirmed:
- keep raw `tag`, `length`, `value`, APDU structure, or BER-TLV tree
- prefer `Unknown / not confidently decoded`
- emit a warning rather than a guessed meaning

## This pass implemented

- fixed REFRESH qualifier `0x08`, `0x09`, and added `0x0A`
- added code comments pointing to the standards/Wireshark source family for core semantic tables
- added golden regression coverage for every REFRESH qualifier from `0x00` through `0x0A`
- added a FETCH response regression case for REFRESH `0x09`
