# M20 Gate B Card Paper Matrix

EXPERIMENTAL - PAPER STUDY ONLY - NO CARD SELECTED - NO GATE CLOSED

## Scope and result

This paper study implements QK-DEC-098. It compares three exact catalog
paths against the seven assertions of QK-TST-BENCH-002 and the matching
QK-F2 experiment templates. It records current sourcing facts and the work
that only an exact card, applet, reader, and registered run can answer.

The paper result is:

- carry the NXP JCOP 4 SECID J3R180 dual-interface configuration forward as
  the lead paper candidate;
- retain NXP.J3D081.DI as a historically documented secp256k1 compatibility
  control, not as the preferred production base; and
- retain FEITIAN A40CR only as a conditional supplier-diversity probe until
  secp256k1 support is established.

No item is a production-card selection. OD-02 remains open,
QK-TST-BENCH-002 remains `PLANNED - NOT RUN`, every QK-F2 experiment below
still has no run registration, and Gate B remains open. No card was bought,
contacted, programmed, or exercised for M20.

## Authority and interpretation boundary

The controlling payload and behavior remain Core Architecture v1 sections
4.5 and 6.1 through 6.5, QK-REQ-CARD-001 through QK-REQ-CARD-010, and
QK-TST-BENCH-002. The imported QK2 set names a card class, not a SKU: an
ID-1 contact ISO-7816/T=1 programmable JavaCard able to host the same fixed
B/C applet. The SEC1210 and MIKROE-5492 are host-interface references, not
candidate cards.

On-card key generation is recorded below only as a capability fact. It is
not the v1 signer-key origin. Under Core Architecture v1 section 4.5, the
terminal derives each BIP48 account xprv from separately generated Seed B or
Seed C and provisions that least-authority account material, its chain code,
origin, fixed role, A2, and D. A future card choice cannot silently replace
that model with card-generated B/C keys.

Generic JavaCard API names do not establish secp256k1, caller-digest signing,
low-S behavior, nonce behavior, transaction atomicity, power-cut recovery,
or physical endurance on a particular card. Those facts remain owed by the
exact-card records named below.

Core Architecture v1 places only the direct contact card bus inside the
trusted terminal boundary. All three catalog paths are dual-interface, so
their paper disposition is conditional: the QuietKey applet and every
bearer-authorized operation must be unreachable over ISO-14443, or the Owner
must explicitly ratify a widened interface before a candidate can advance.
M20 authorizes no contactless QuietKey path.

## Fact classifications

Every paper finding uses exactly one QK-DEC-098 classification:

| Classification | Meaning in this document |
|---|---|
| `direct documentation` | A pinned static primary manufacturer/platform technical document states the fact for the named controller or family. It is still not a physical M20 observation. |
| `vendor claim` | A dynamic manufacturer, project-vendor, or seller page, or a seller-authored draft sheet, states the fact. It was not reproduced on a specimen. |
| `inference` | A bounded paper deduction from registered sources; it is never treated as observed behavior. |
| `unresolved` | The registered public sources do not establish the required fact. |

The `Future exact-card record` column is always `unresolved`; it names what
the later registered run must measure or demonstrate.

## Candidate shortlist and dated sourcing

All prices and availability are snapshots from 2026-08-25, exclude any cost
not expressly included by the seller, and authorize no acquisition.

| ID | Exact catalog identity | Platform, form, and loading path | Single-unit sourcing snapshot | Paper disposition | Source-linked uncertainty |
|---|---|---|---|---|---|
| C1 | NXP JCOP 4 SECID `J3R180 (Dual-Interface)` with `SCP03-10`; CardLogix variation `46905`, SKU `3900157` | JCOP 4 / Java Card 3.0.5 Classic / GlobalPlatform 2.3; ID-1-size dual-interface seller configuration; GlobalPlatform loading route | CardLogix, US: USD 11.95, in stock, configured variation. Cardomatic, Germany: EUR 17.80 excluding VAT and delivery, in stock, `J3R180 JCOP 4 SecID`; its SCP configuration is not stated. | Carry forward as lead paper candidate; no specimen or batch selected | No public primary source names secp256k1 for the exact configured card. The CardLogix snapshot also contains a duplicate matching variation `51632`, SKU `9001543`; variation `46905` is used here because its response carries explicit in-stock markup and finite quantity, but supplier identity confirmation remains owed. Destination-specific delivery, hardware revision, management-key custody, and exact library options are unresolved. |
| C2 | NXP `NXP.J3D081.DI`, J3D081 JCOP v2.4.2 R2, dual-interface | P5CD081; Java Card 3.0.1 Classic / GlobalPlatform 2.2.1; 1FF ID-1; SCP02 default with other SCP profiles project-dependent | MoTechno, Germany: EUR 29.99 excluding 19% VAT and shipping, add-to-cart, MOQ 1; seller requires a verified business customer and warns of export controls. | Retain as historically documented secp256k1 compatibility control; not the preferred production base | The platform is old, public longevity is not established, SHA-512 is absent from the exact seller sheet, and the cited third-party applet is not the QuietKey applet. |
| C3 | FEITIAN `SC-JAVA-A40CR-WO-APPLET`, MPN `C020400`, A40CR without ePass2003 applet | Infineon SLE77-based FT-JCOS; Java Card 3.0.4 / GlobalPlatform 2.1.1; dual-interface; no ePass2003 applet installed | FEITIAN US-locale exact variant `31445690941483`: USD 17.65, in stock, US storefront; taxes and shipping are not included in the recorded fact. | Retain conditionally as supplier-diversity probe | Public model material says only generic ECC; secp256k1, exact ECDSA profile, RNG, endurance, transaction-buffer size, card dimensions, and tear behavior are unresolved. |

## Seven-assertion oracle alignment

The matrix does not redefine an assertion. Each key is the corresponding
QK-TST-BENCH-002 item and future experiment:

| Key | QK-TST-BENCH-002 assertion | Required exact-card content | Future experiment |
|---|---|---|---|
| a | secp256k1 signing correctness and performance | Private-key import, capability-only native keygen, raw 32-byte-digest ECDSA, strict DER, low-S, nonce construction, signature verification, and latency distribution | QK-F2E-004 |
| b | least-authority-payload derivation behavior | Persistent account xprv/chain/origin storage, account-xpub return, non-hardened `{0,1}/index` derivation, key-origin correctness, index boundary, and timing | QK-F2E-011 |
| c | on-card RNG characterization | Primitive/source, sample access, throughput, health claims, and relationship to signing nonces; API presence cannot establish entropy quality | QK-F2E-012 |
| d | APDU behavior including byte layouts | ISO-7816/T=1, voltage, ATR, APDU sizing/chaining/reset/session semantics, per-operation latency/timeout/variance, applet loading, contactless exclusion, SEC1210 reachability, and commodity-CCID reachability | QK-F2E-003 |
| e | write atomicity and power-cut behavior | Transaction capacity, `BEGIN/DATA/COMMIT/ABORT` feasibility, lifecycle commit point, interruption states, rollback/resume behavior, and absence of ambiguous third states | QK-F2E-005 |
| f | storage endurance | NVM technology, guaranteed cycles/retention, transaction-buffer wear, write amplification, degradation indicators, and irreversible-operation constraints | QK-F2E-014 |
| g | distinct B/C signer identities carrying the same A2 and D | Same applet, fixed different roles, distinct provisioned account keys, byte-identical A2/D, A2 export, D/`wallet_id` readback and binding, path/policy enforcement, and normal-operation signer-private-key non-exportability | QK-F2E-013 is a partial anchor for signer identities and A2 only; shared D, fixed roles, `wallet_id`, path/policy, lifecycle guards, and signer non-exportability lack a current QK-F2 template |

## Candidate-by-assertion matrix

| Candidate | Key / future experiment | Paper finding | Classification | Future exact-card record (`unresolved`) |
|---|---|---|---|---|
| C1 | a / QK-F2E-004 | The configured-card seller states ECC key generation, ECDSA, SHA-512, and an ECC accelerator. Satochip identifies J3R180 as able to host its BIP32 applet, which is a compatibility route only. | `vendor claim` | Named secp256k1 import/keygen, raw-digest ECDSA, strict DER, low-S, nonce behavior, verification, latency distribution, and whether required libraries are enabled in the delivered variation. |
| C1 | b / QK-F2E-011 | The seller states 180 KB user memory and SHA-512, and the Satochip page states a BIP32 applet route on J3R180. Neither source describes the QuietKey least-authority payload. | `vendor claim` | Import the pre-derived BIP48 account xprv plus chain/origin, return the account xpub, derive only non-hardened branch/index children, enforce the bound, and measure timing. |
| C1 | c / QK-F2E-012 | The configured-card seller states an AIS31 true random generator and a DRG.3 pseudorandom generator. | `vendor claim` | Identify the delivered primitive and API, collect registered samples, characterize throughput/health behavior, and determine exactly how signing nonces are formed. |
| C1 | d / QK-F2E-003 | The seller states ISO-7816 T=0/T=1 with T=1 default, ISO-14443 T=CL, GlobalPlatform loading, and the selected SCP03-10 profile. | `vendor claim` | Record exact ATR, voltage, short/extended APDU limits, chaining/reset/session behavior, per-operation latency/timeout/variance, management-key state, byte layouts, proof that QuietKey bearer operations are unreachable over contactless, the SEC1210 path, and commodity-CCID behavior. |
| C1 | e / QK-F2E-005 | Java Card 3.0.5 and writable NVM provide a plausible implementation route, but the generic platform label says nothing about the delivered commit buffer or interruption states. | `inference` | Implement the registered lifecycle on a sacrificial specimen and cut power across every operation boundary, recording rollback, recovery, and any third state. |
| C1 | f / QK-F2E-014 | The configured-card seller states at least 500,000 write cycles and at least 25 years retention. | `vendor claim` | Confirm the delivered NVM technology and guarantees, then measure write amplification, transaction-buffer wear, endurance, retention basis, and degradation behavior. |
| C1 | g / QK-F2E-013 partial | The stated memory and programmable applet surface are sufficient only to make the B/C state model plausible; they do not establish it. | `inference` | Provision two specimens with distinct terminal-derived account keys and fixed B/C roles but identical A2/D; prove A2 export, D/`wallet_id` binding, path policy, lifecycle guards, and signer-private-key non-exportability in normal operation. QK-F2E-013 covers only identities and A2; the remainder needs a separately ratified template or template expansion. |
| C2 | a / QK-F2E-004 | The exact seller sheet states on-card ECC GF(p) key generation through 320 bits. The pinned Satochip applet names J3D081 as tested and sets secp256k1/BIP32 parameters; that is not QuietKey behavior. | `vendor claim` | Reproduce secp256k1 import/keygen and raw-digest ECDSA on the exact card; establish strict DER, low-S, nonce behavior, verification, and latency distribution. |
| C2 | b / QK-F2E-011 | The pinned Satochip applet documents a BIP32 import/derivation route on J3D081, while the exact seller sheet exposes only SHA-1/SHA-224/SHA-256 and 80 KB EEPROM. | `vendor claim` | Establish a QuietKey account-xprv/chain/origin implementation without assuming native SHA-512; check account-xpub return, branch/index derivation, origin, bound, and timing. |
| C2 | c / QK-F2E-012 | NXP's P5CD081 family sheet states a hardware low-power AIS31-compliant RNG. | `direct documentation` | Identify the JCOP exposure on the delivered card, collect samples, characterize throughput/health behavior, and determine signing-nonce construction. |
| C2 | d / QK-F2E-003 | The exact seller page and sheet state T=1, a fixed ATR, IFSC 254, Java Card 3.0.1, GlobalPlatform 2.2.1, and SCP02 by default. | `vendor claim` | Reproduce ATR and voltage behavior; measure APDU limits/chaining/reset/session semantics and per-operation latency/timeout/variance; prove that QuietKey bearer operations are unreachable over contactless and establish SEC1210 plus commodity-CCID reachability. |
| C2 | e / QK-F2E-005 | A Java Card transaction route is plausible, but neither the exact seller sheet nor the controller sheet establishes application-level lifecycle atomicity under interruption. | `inference` | Measure transaction capacity and cut power through provision, commit, abort, and recovery on sacrificial specimens. |
| C2 | f / QK-F2E-014 | NXP's P5CD081 family sheet states 500,000 write cycles typical and 25 years retention minimum. | `direct documentation` | Confirm the exact delivered controller/revision, characterize application write amplification and transaction wear, and run the registered endurance procedure. |
| C2 | g / QK-F2E-013 partial | Existing BIP32 applet compatibility makes a custom B/C applet route plausible, but no source implements QuietKey role, A2, D, `wallet_id`, or lifecycle semantics. | `inference` | Perform the complete two-specimen shared-A2/D and distinct-role/key record, including A2 export and normal-operation signer-private-key non-exportability. QK-F2E-013 covers only identities and A2; the remainder needs a separately ratified template or template expansion. |
| C3 | a / QK-F2E-004 | FEITIAN states generic ECC, an FEITIAN crypto library, and SHA-512, but does not name secp256k1 or native ECC key generation for A40CR. | `vendor claim` | Establish curve acceptance, private-key import, capability-only keygen, raw-digest ECDSA, strict DER, low-S, nonce behavior, verification, and timing before carrying the candidate farther. |
| C3 | b / QK-F2E-011 | Generic ECC, SHA-512, 32 KB NVM, and an applet-loading surface make a custom derivation route conceivable but establish no BIP32 operation. | `inference` | Establish whether the complete least-authority payload fits and whether exact BIP48 account-child derivation, account-xpub return, origin checks, bounds, and timing are implementable. |
| C3 | c / QK-F2E-012 | No registered A40CR source states an RNG primitive, certification profile, sample path, or signing-nonce relationship. | `unresolved` | Identify and characterize the delivered RNG and signing-nonce behavior using QK-F2E-012. |
| C3 | d / QK-F2E-003 | FEITIAN states ISO-7816 T=1, ISO-14443 T=CL Type A, Java Card 3.0.4, GlobalPlatform 2.1.1, third-party applet compatibility, and a blank no-ePass2003 configuration. | `vendor claim` | Record ATR, voltage, APDU limits/chaining/reset/session semantics, per-operation latency/timeout/variance, applet loading and management state, proof that QuietKey bearer operations are unreachable over contactless, the SEC1210 path, and commodity-CCID behavior. |
| C3 | e / QK-F2E-005 | A programmable Java Card route is plausible; no registered A40CR source states commit capacity, tear behavior, or recovery states. | `inference` | Implement and power-cut the complete lifecycle on sacrificial specimens, including every transition and possible third state. |
| C3 | f / QK-F2E-014 | No registered A40CR source states a numeric write-cycle or retention guarantee. | `unresolved` | Obtain exact NVM guarantees for the delivered revision and run the registered wear/endurance procedure. |
| C3 | g / QK-F2E-013 partial | The blank applet surface and 32 KB NVM make a B/C representation conceivable but establish none of the shared or distinct state properties. | `inference` | Prove distinct terminal-derived keys and roles, byte-identical A2/D, A2 export, D/`wallet_id` binding, path policy, lifecycle guards, and normal-operation signer-private-key non-exportability. QK-F2E-013 covers only identities and A2; the remainder needs a separately ratified template or template expansion. |

## Cross-cutting contract gaps

| Contract item | C1 | C2 | C3 | Required future record |
|---|---|---|---|---|
| Atomic one-time provisioning and one commit point | `unresolved` | `unresolved` | `unresolved` | QK-F2E-005 plus a future role/payload template expansion; no platform transaction name substitutes for power-cut behavior. |
| A2 persistent storage and bearer-authorized export | `unresolved` | `unresolved` | `unresolved` | Exact payload bytes, readback behavior, lifecycle guards, and no PIN/password/pairing/vendor-account dependency. |
| Fixed role and D/`wallet_id` binding | `unresolved` | `unresolved` | `unresolved` | Two-card record with different roles and account keys, same A2/D, exact readback, and rejected cross-wallet/path requests. |
| Signer private key non-exportability in normal operation | `unresolved` | `unresolved` | `unresolved` | Mechanism and black-box demonstration, with rescue behavior documented without weakening the fixed Core v1 rule. |
| Commodity CCID reachability | `inference` from T=1 | `inference` from T=1 | `inference` from T=1 | ATR, PC/SC, short and extended APDUs, removal/reinsertion, and open rescue-tool path on the selected reader. |
| Contactless bearer-operation exposure | `unresolved` | `unresolved` | `unresolved` | Prove the QuietKey applet and every bearer-authorized operation are unreachable over ISO-14443, or obtain an explicit Owner decision before advancement. |
| Bus-pass-style ID-1 exterior | `vendor claim` | `vendor claim` | `inference` from product class | Exact delivered dimensions, print/branding state, antenna/contact form, and QK-REQ-CARD-007 presentation check. |
| Production availability and lifecycle | `unresolved` beyond two dated stock pages | `unresolved`; legacy controller | `unresolved` beyond one dated stock page | Manufacturer lifecycle notice, exact revision/batch identity, repeatable supply, region, MOQ, and unit economics. |

## Source map

External sources are registered in `docs/SOURCE-REGISTER.md`; none is
authority for QuietKey requirements and no external code or document was
imported.

- J3R180: [CardLogix configured product](https://www.cardlogix.com/product/nxp-jcop-4-java-card-3-0-5-classic/), [Cardomatic EU listing](https://www.cardomatic.de/en/p/j3r180-card), [NXP P71D321 fact sheet](https://cache.nxp.com/docs/en/fact-sheet/P71D321.pdf), and [Satochip J3R180 applet-loading guide](https://satochip.io/build-your-own-satochip-hardware-wallet/).
- J3D081: [MoTechno exact product](https://www.motechno.com/product/j3d081-dual-interface-javacard-3-0-1/), [MoTechno exact-card sheet](https://www.motechno.com/wp-content/uploads/J3D081-JCOP2.4.2-1.pdf), [NXP P5CD081 family sheet](https://cache.nxp.com/docs/en/data-sheet/P5CD016_021_041_Cx081_FAM_SDS.pdf), and pinned SatochipApplet commit `8cbaa1d6531df7e20c7a3d47d95766db51d9a136`.
- A40CR: [FEITIAN US exact variant](https://ftsafe.us/products/feitian-java-card-without-epass2003-applet-a40cr?country=US&variant=31445690941483), [FEITIAN global A40CR page](https://www.ftsafe.com/store/product/dual-interface-java-card-smart-card-with-cc-eal5/), and [Infineon SLE77 jTOP ID Flex product brief](https://www.infineon.com/dgdl/Infineon-jTOP_ID_Flex-PB-v04_17-EN.pdf?fileId=5546d4624cb7f111014d56a031077a88) as controller-family context only.

## Gate B remainder

The paper matrix leaves all physical and protocol outcomes open. Before Gate
B can close, the Owner must still select an exact production card/revision
through OD-02; authorize, register, and execute the seven exact-card records;
resolve and publish the APDU protocol and limits; demonstrate low-S signing,
policy/path enforcement, the complete B/C shared/distinct state model,
atomic lifecycle behavior, endurance, RNG behavior, SEC1210 reachability,
commodity-CCID rescue, contactless exclusion, and normal-operation signer
private-key non-exportability. Assertion (g) also needs a separately
ratified experiment-template expansion beyond QK-F2E-013's identities/A2
scope. M20 supplies no measurement record for any of those obligations.
