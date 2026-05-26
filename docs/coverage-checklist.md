# Coverage Checklist

Focused coverage review against ETSI TS 102 221, ETSI TS 102 223, ISO/IEC 7816-4, GlobalPlatform, public GSMA SGP.22/SGP.23 tag usage, and Wireshark dissector coverage.

| Command / tag / code | Standard / source | Supported | Test added |
| --- | --- | --- | --- |
| `SELECT FILE` | ISO/IEC 7816-4 | Yes | Yes |
| `SELECT` response templates `62` / `6F` / `64` (`FCP` / `FCI` / `FMD`) | ISO/IEC 7816-4 / ETSI TS 102 221 / Wireshark `packet-gsm_sim.c` | Yes | Yes |
| `SELECT` response tags `80`, `81`, `82`, `83`, `84`, `88`, `8A`, `A5`, `AB`, `C6` | ISO/IEC 7816-4 / ETSI TS 102 221 / Wireshark `packet-gsm_sim.c` | Yes | Yes |
| File ID naming for `MF`, common EFs, and AID-based ADF / Security Domain identification | ETSI TS 102 221 / GlobalPlatform / public eUICC AID references | Yes | Yes |
| `STATUS` | ISO/IEC 7816-4 / ETSI TS 102 221 | Yes | Existing |
| `READ BINARY` | ISO/IEC 7816-4 | Yes | Yes |
| `UPDATE BINARY` | ISO/IEC 7816-4 | Yes | Structural coverage |
| `READ RECORD` | ISO/IEC 7816-4 | Yes | Structural coverage |
| `UPDATE RECORD` | ISO/IEC 7816-4 | Yes | Structural coverage |
| `SEARCH RECORD` | ISO/IEC 7816-4 | Yes | Structural coverage |
| `VERIFY / CHANGE / DISABLE / ENABLE / UNBLOCK` | ISO/IEC 7816-4 | Yes | Partial |
| `GET RESPONSE` | ISO/IEC 7816-4 | Yes | Covered by SW/response flow |
| `GET DATA / PUT DATA` | ISO/IEC 7816-4 | Yes | Partial |
| `MANAGE CHANNEL` | ISO/IEC 7816-4 | Yes | Structural coverage |
| `AUTHENTICATE` | ISO/IEC 7816-4 / ETSI TS 102 221 | Yes | Existing |
| `TERMINAL CAPABILITY` (`INS=AA`, `A9` template) | ETSI TS 102 221 / Wireshark `packet-gsm_sim.c` | Yes | Yes |
| `MANAGE LSI` | ETSI TS 102 221 / SGP.22 additions | Yes | Yes |
| `TERMINAL PROFILE` | ETSI TS 102 223 / 3GPP TS 31.111 / Wireshark CAT dissector | Yes | Yes |
| `ENVELOPE` | ETSI TS 102 223 / 3GPP TS 31.111 | Yes | Existing |
| `FETCH` | ETSI TS 102 223 / 3GPP TS 31.111 | Yes | Yes |
| `TERMINAL RESPONSE` | ETSI TS 102 223 / 3GPP TS 31.111 | Yes | Yes |
| CAT TLVs: `Command Details`, `Device Identities`, `Result`, `Duration`, `Alpha Identifier`, `Address`, `Text String`, `Item`, `File List`, `Channel Data`, `Bearer Description` | ETSI TS 102 223 / Wireshark CAT dissector | Yes | Existing |
| CAT TLVs: `USSD String`, `Default Text`, `Icon Identifier`, `Browser Identity`, `URL`, `Buffer Size`, `File Update Information`, `Channel Status` | ETSI TS 102 223 / Wireshark CAT dissector | Yes | Regression via parser path |
| Proactive command types: `REFRESH`, `POLL INTERVAL`, `OPEN/CLOSE CHANNEL`, `SEND/RECEIVE DATA`, `GET CHANNEL STATUS`, `PROVIDE LOCAL INFORMATION`, `SET UP MENU`, `DISPLAY TEXT`, `GET INPUT`, `RUN AT COMMAND (0x34)`, `LANGUAGE NOTIFICATION (0x35)`, `SET FRAMES (0x50)`, `GET FRAMES STATUS (0x51)`, `ACTIVATE (0x70)`, `CONTACTLESS STATE CHANGED (0x71)`, `COMMAND CONTAINER (0x72)`, `ENCAPSULATED SESSION CONTROL (0x73)`, `LSI Command / Manage LSI (0x79)` | ETSI TS 102 223 Release 17 baseline / Wireshark CAT dissector | Yes | Partial |
| `INSTALL`, `LOAD`, `DELETE`, `PUT KEY`, `INITIALIZE UPDATE`, `EXTERNAL AUTHENTICATE`, `GET STATUS`, `STORE DATA`, `SET STATUS` | GlobalPlatform | Yes | Yes / partial |
| `INITIALIZE UPDATE` response | GlobalPlatform | Yes | Yes |
| `GET STATUS` registry BER-TLV response | GlobalPlatform | Yes | Yes |
| ES10 ASN.1 tags `BF20`, `BF21`, `BF22`, `BF23`, `BF24`, `BF25`, `BF26`, `BF27`, `BF28`, `BF29`, `BF2A`, `BF2B`, `BF2D`, `BF2E`, `BF30`, `BF31`, `BF32`, `BF33`, `BF34`, `BF38`, `BF3C`, `BF3E`, `BF3F`, `BF43`, `E3` | GSMA SGP.22 / SGP.23 public tag usage and Android Open Source eUICC tag mappings | Yes | Yes |
| `9000`, `91xx`, `61xx`, `62xx`, `63Cx`, `67 00`, `68 81/82`, `69 82/83/84/85/86`, `6A 80/81/82/83/84/86/87/88`, `6B 00`, `6D 00`, `6E 00`, `6F 00`, `93 00` | ISO/IEC 7816-4 / telecom smart card practice / Wireshark | Yes | Yes |

## Known gaps after this pass

| Item | Standard / source | Supported | Test added |
| --- | --- | --- | --- |
| Stateful command/response pairing across multiple log lines | Protocol-analyzer behavior | No | No |
| Deeper proprietary sub-tag naming inside all FCP/FCI/FMD variants after `SELECT` / `STATUS` | ISO/IEC 7816-4 / ETSI TS 102 221 / GlobalPlatform | Partial | Partial |
| Full SCP02/SCP03 cryptogram semantic decoding | GlobalPlatform | Partial | No |
| Full ES10 ASN.1 semantic field decoding beyond top-level tag identification | GSMA SGP.22 / SGP.23 | Partial | No |
| Full CAT command-specific payload semantics for every proactive command | ETSI TS 102 223 / 3GPP TS 31.111 | Partial | No |
