EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

# OD-08 Licensing and Governance Decision Packet (Non-Binding)

STATUS: OWNER-AUTHORIZED DECISION INPUT ONLY — NON-NORMATIVE — OD-08 OPEN — ALL OPTIONS UNSELECTED — THIS PACKET GRANTS NO RIGHTS — NO ROLE APPOINTED OR CHANNEL CONFIGURED — NO RELEASE OR GATE CHANGE.

Preparation of this packet was authorized by the owner record
QK-AUTH-OD08-PKT-001. Publication is not authorized by QK-AUTH-OD08-PKT-001 and
requires a later explicit owner instruction after a passing independent audit. No
content, option, license, policy, role, or channel in this packet was adopted,
selected, or configured by that authorization. This packet is not legal advice. The
owner and qualified counsel must confirm the rights and chain-of-title position
before any license grant or application is made.

## 1. Scope and non-effect

This packet is decision INPUT for open decision OD-08 only. It inventories verified
repository facts, compares unselected standard license families for information, and
lists the owner questions that must be answered before any later, separately
authorized application chain. It changes no status, resolves no open decision,
grants no rights, appoints no person, and configures no repository, hosting, or
reporting setting.

## 2. Verified repository facts at published parent e81ab9c61dda9be60ac45facbe5db57115578540

- No project-applied `SPDX-License-Identifier` header, manifest license field, or
  project-license expression applies to QuietKey at this parent, and no current
  project license file exists; the repository has no selected project license.
  Source Register rows cite third-party license identifiers for provenance without
  applying them to QuietKey.
- The workspace has zero third-party/registry dependencies; `host/qk-host-sim` has
  one first-party path dependency on `host/qk-host-model`; both host crates declare
  `publish = false`.
- The Source Register rows are citation/provenance records only; they do not license
  QuietKey and import no third-party license text.
- Gates A–E are OPEN and STOP-SHIP is in force; there is no release, tag, or
  supported version.
- Historical fact: an MIT license text existed at repository root in commit
  `1adce1afa1e6cf6cc22287af54c2a7a3a8e2458e` and was removed in commit
  `8f7ce227db21299d831636243ab76b110a875f73`. This packet does NOT claim that the
  removal revoked any rights that recipients of those historical versions may have
  obtained; that question is reserved for counsel (see OD08 question 015 below).
- Git author labels are commit metadata only; they are not proof of authorship or
  chain of title.

## 3. Rights and chain-of-title precondition

Before any grant or application, the owner must establish, with evidence or written
attestation, all rights and authority needed for every contemplated grant — not
copyright over files alone: copyright; patent and invention authority; database
rights where applicable; moral-right consents or waivers where legally possible;
trademark and branding rights; employment and contract terms; and rights covering
third-party material and material introduced through human, service, or agent
commits — together with any assignments, consents, exclusions, or rewrites
required. This packet makes no legal conclusion about any of these. No copyright
ownership is asserted by this packet and no contributor consent is assumed.

## 4. Unselected candidate matrix

Every row below has status UNSELECTED. Starting recommendations are informational
only and are subject to the rights review above. Content classifications used in
this packet are non-exclusive and non-exhaustive; a path or file may fall into
multiple categories, and mixed-content boundaries must be identified before any
choice is applied.

| Domain | Starting recommendation (UNSELECTED) | Alternatives (UNSELECTED) | Notes |
| --- | --- | --- | --- |
| Software | Apache-2.0, only after rights/legal review | MIT; MPL-2.0 | Apache-2.0 carries express patent provisions with termination on patent aggression and notice obligations; MIT is simpler and has no express patent-license text; MPL-2.0 adds file-level source reciprocity. An optional `MIT OR Apache-2.0` expression gives each recipient the CHOICE of either license; it does not automatically apply both — Apache-only versus that recipient choice is a tradeoff for the owner and counsel. |
| Hardware designs | CERN-OHL-W-2.0 | CERN-OHL-P-2.0; CERN-OHL-S-2.0 | CERN-OHL-P is permissive, CERN-OHL-W is weakly reciprocal, CERN-OHL-S is strongly reciprocal; W as a starting candidate balances share-back of modified design source with less scope than S. Any such license applies to hardware design/source materials and to product obligations only as defined by the chosen text; it is never a safety certification. No safety certification exists or is implied. |
| Documentation | CC-BY-4.0 | CC-BY-SA-4.0 | CC-BY requires attribution and marking of changes; CC-BY-SA adds ShareAlike for adaptations. Creative Commons itself recommends against applying CC licenses to software, while software documentation may use CC; code snippets mixed into documentation must be handled separately. |
| Public vectors/fixtures/data | CC0-1.0 where legally effective | A separately selected explicit license where CC0-1.0 is not effective | CC0-1.0 is a waiver plus a fallback public license where the waiver is not effective; it carries no attribution condition and does not settle patent or trademark rights. Gateware, artwork/logo, fonts, and manufacturing outputs each need explicit classification before any choice. |
| Contributions | A separately enacted inbound=outbound rule, plus DCO 1.1 sign-off | CLA only if a specific need justifies it | DCO 1.1 is a certification of submission authority, not an inbound license, assignment, or rights grant. Indefinite public sign-off records and privacy, corporate authority, service/agent contributions, and exception handling must all be addressed. Nothing is activated by this packet. |
| Governance | Protected security/release/license/governance changes require the author plus two independent human approvers (three people); routine changes require at least one non-author reviewer | — | Independent means no self-review, no shared account, and no material authorship of or conflict of interest in the reviewed change. Absent such staffing, protected changes remain blocked. No identity is appointed. |
| Vulnerability process | Named owner and backup, a monitored private channel, and access/retention/acknowledgment/disclosure/escalation rules, all before any release | — | GitHub private vulnerability reporting may be EVALUATED; it is not enabled by this packet. |
| Release | Release by two authorized human releasers, both independent of every material artifact preparer or builder; reproducible-build match; a signed annotated tag; a signed release manifest or attestation that JOINTLY binds the exact annotated tag object, the exact commit SHA, every artifact digest, and the provenance/reproducible-build record; a protected release ref or external transparency anchor (a tag ref is not inherently immutable); a public verification procedure; separated key custody with revocation and rotation | — | The release act is a separate control from prior change review; the exact permissible overlap with prior reviewers remains an owner question. No mechanism or setting is enabled; scheme and custodians remain open. |
| Versions | Publish and retain an explicit no-support notice until a first separately approved supported release, then define the support window, end of life, and backport policy | — | Current fact: No versions of any kind are supported; no security-support promise or policy is approved. |
| Audit | Independent qualified reviewer with conflict disclosure and a defined scope, remediation, retest, and publication process | — | Audit evidence, remediation, or retest never closes a gate or accepts residual risk; those require a separate owner record. No auditor is appointed. |
| Trademark / official builds | Separate policy required for names, logos, and official-build claims | — | A copyright license over a logo and trademark/official-build permission can overlap but are separate; an open or CC license alone does not settle mark use. Outside the license decision itself. |

## 5. Owner decision questions

Each response cell below must remain exactly `OWNER RESPONSE REQUIRED — UNSELECTED`
until the owner answers. For any question the owner may instead answer
`DEFER — REMAINS OPEN`, which is an allowed response and leaves that question open.

| Question | Subject | Response |
| --- | --- | --- |
| OD08-Q-001 | Exact rights and authority position for every contemplated grant — copyright; patent/invention authority; database rights where applicable; moral-right consents or waivers where legally possible; trademark/branding rights; employment/contract terms; and third-party and human/service/agent material — with evidence or attestation plus any assignments, consents, exclusions, or rewrites. | OWNER RESPONSE REQUIRED — UNSELECTED |
| OD08-Q-002 | Classification, by path/file, into non-exclusive and non-exhaustive categories (software, hardware source, documentation, data/vectors/fixtures, gateware, artwork/font/logo, packaging/manufacturing, trademark, third party), allowing multiple categories per file and identifying mixed-content boundaries. | OWNER RESPONSE REQUIRED — UNSELECTED |
| OD08-Q-003 | Exact software license or expression and the rationale for it. | OWNER RESPONSE REQUIRED — UNSELECTED |
| OD08-Q-004 | Exact license for future hardware-design/source artifacts and any obligations for products made from them. | OWNER RESPONSE REQUIRED — UNSELECTED |
| OD08-Q-005 | Exact documentation license and its scope. | OWNER RESPONSE REQUIRED — UNSELECTED |
| OD08-Q-006 | Licenses or status for vectors, fixtures, data, gateware, artwork, fonts, logos, and manufacturing outputs. | OWNER RESPONSE REQUIRED — UNSELECTED |
| OD08-Q-007 | Whether external contributions are accepted; a separately enacted inbound=outbound rule plus DCO sign-off, or a CLA; sign-off, authority, and exception process. | OWNER RESPONSE REQUIRED — UNSELECTED |
| OD08-Q-008 | Primary and backup maintainers/roles, their scope, least privilege, and succession/removal/conflict rules. | OWNER RESPONSE REQUIRED — UNSELECTED |
| OD08-Q-009 | Review thresholds by risk and path, required approvers, independence requirements, and any break-glass procedure. | OWNER RESPONSE REQUIRED — UNSELECTED |
| OD08-Q-010 | Vulnerability-report owner, private channel and backup, monitoring, acknowledgment, access, retention, disclosure, and escalation. | OWNER RESPONSE REQUIRED — UNSELECTED |
| OD08-Q-011 | Release/tag/artifact signing and provenance scheme, authorization, key custody, backup, rotation, revocation, and compromise handling. | OWNER RESPONSE REQUIRED — UNSELECTED |
| OD08-Q-012 | Supported versions, support window, end of life, backports, notifications, and explicit no-promise language. | OWNER RESPONSE REQUIRED — UNSELECTED |
| OD08-Q-013 | Audit coordination owner, independence/qualifications/conflicts, scope, publication, and remediation/retest. | OWNER RESPONSE REQUIRED — UNSELECTED |
| OD08-Q-014 | Control of names, logos, and official-build claims, and trademark/non-endorsement policy. | OWNER RESPONSE REQUIRED — UNSELECTED |
| OD08-Q-015 | Effective date and scope of any future grant, treatment of historical MIT-published versions, retroactivity and future contributions, governing jurisdiction, and counsel sign-off. | OWNER RESPONSE REQUIRED — UNSELECTED |

An owner answer to any question is direction input only. Partial answers leave
OD-08 open. All 15 questions are separately answerable. Closing OD-08 requires a
later explicit owner record made after the rights and legal review. The actual
license files, SPDX expressions, manifest fields, policies, and repository or
hosting settings require an even later, separately authorized application chain.

## 6. Separate later decision and application sequence

1. Owner answers (any subset of) the questions above; each answer is recorded as
   direction input only.
2. Rights/chain-of-title review and counsel confirmation complete.
3. A separate explicit owner record selects the licenses and policies and closes or
   narrows OD-08.
4. A separately authorized application chain — not this one — introduces license
   files, expressions, manifest fields, policy documents, and any repository or
   hosting configuration, each under its own verification.

## 7. Informational primary sources

Each link below is UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED. No standard
license text is copied into this repository and no Source Register row is added by
this packet. Links may drift; none is a pinned source.

- https://spdx.org/licenses/ — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://www.apache.org/licenses/LICENSE-2.0 — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://opensource.org/license/mit — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://www.mozilla.org/en-US/MPL/2.0/ — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://cern-ohl.web.cern.ch/ — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://creativecommons.org/licenses/by/4.0/legalcode.en — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://creativecommons.org/licenses/by-sa/4.0/legalcode.en — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://creativecommons.org/publicdomain/zero/1.0/legalcode.en — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://creativecommons.org/faq/#can-i-apply-a-creative-commons-license-to-software — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://developercertificate.org/ — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://opensource.org/osd — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-tags — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://doc.rust-lang.org/cargo/reference/manifest.html — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED

END OF PACKET — OD-08 REMAINS OPEN — OWNER RESPONSES AND A SEPARATE RECORDED APPLICATION AUTHORIZATION ARE REQUIRED.
