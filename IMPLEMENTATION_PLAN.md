# Implementation Plan — Closing the adscan Feature Gap

Companion to [`TODO.md`](./TODO.md). That file lists *what* is missing; this file is *how* to
build it, grounded in ad-autopwn's actual architecture. Line references are to `ad-autopwn.py`
as of this writing (v4.13.0, ~10,400 lines).

---

## 0. Architecture recap — the five extension points

ad-autopwn is a **single-file orchestrator**: every capability is a `run_*(cfg: Config) -> bool`
function that shells out through one executor. Adding a technique almost always means wiring one
of these five seams — you rarely write protocol code, you drive an existing tool (`nxc`,
`certipy`, `bloodyAD`, `impacket-*`).

| # | Seam | Where | Use it to add… |
|---|------|-------|----------------|
| 1 | **`run(cmd, cfg, …)`** | `ad-autopwn.py:407` | Any external-tool invocation. Honors `--dry-run`, bg, timeout, `outfile`. **Never call `subprocess` directly.** |
| 2 | **`Config` dataclass** | `:129` | New options/flags + runtime state. Add field → wire in `parse_args()` (`:9193`). |
| 3 | **`--phase` choices + `match cfg.phase`** | `:9373` and `:9521` | A new standalone phase (e.g. `mssql`, `rodc`, `trusts`). |
| 4 | **nxc battery `runs` list + `consume_nxc_findings`** | `:7390` / `:7555` | A new *detection* that runs post-auth and feeds findings. |
| 5 | **`_BH_AUTO_ACTION_MAP` + `_bh_auto_action`** | `:7815` | Auto-firing a primitive off a BloodHound ACL edge. |

Auth is already abstracted — reuse these, don't rebuild:
`cfg.auth_args` / `cfg.auth_string` (impacket), `_nxc_auth_args(cfg)` (`:472`),
`_bloody_auth_args(cfg)` (`:479`). `tool_exists(name)` (`:495`) gates optional deps.
`ok()/detail()/log/phase_header()/success_box()` are the output convention.

### Reusable recipe A — add a new phase

1. Write `run_<name>(cfg: Config) -> bool`. First line: `phase_header("…")`. Gate optional
   tools with `tool_exists(...)`. Every command goes through `run(...)`.
2. Add `"<name>"` to the `--phase` `choices=[…]` list (`:9373`).
3. Add a `case "<name>":` block in `main()`'s `match cfg.phase` (`:9521`+), with the same
   `if not cfg.has_creds: log.error(...); sys.exit(1)` guard the sibling phases use.
4. If it belongs in the zero-to-DA chain, add a gated call inside `run_full_auto()` (`:8711`)
   behind a `cfg.no_<name>` flag.
5. Add any `--<name>-*` options as `Config` fields + `parse_args()` wiring.

### Reusable recipe B — add a detection module

1. Append a tuple to the `runs` list in `run_nxc_enrichment()` (`:7390`):
   `("<label>", "<proto>", <target>, "<module>", [<extra args>])`.
2. Add a parser branch in `consume_nxc_findings()` (`:7555`) that reads `nxc-<label>.txt`,
   extracts the `[+]` findings, appends creds to `extracted_creds` / flags to `summary_lines`.
3. **Verify the exact nxc module name** against the installed `nxc` version before shipping
   (module names drift between releases).

### Reusable recipe C — weaponize a BloodHound edge

1. Add `(right, target_type) -> "action"` to `_BH_AUTO_ACTION_MAP`.
2. Add an `elif action == "…":` dispatch arm in `_bh_auto_action()` (`:7845`) calling your
   `run_*` primitive. The cap (8) and de-dupe are already handled.

---

## Milestone 1 — MSSQL suite  — ❌ DESCOPED

The MSSQL family (10 techniques) is intentionally **out of scope** per owner decision. Left
here as a heading only so milestone numbering below is stable. No work planned.

---

## Milestone 2 — Weaponize detected ACL edges  — ✅ DONE (v4.13.0)

**Shipped.** Implemented as bloodyAD-driven primitives, auto-fired from BloodHound edges via
`_BH_AUTO_ACTION_MAP` + `_bh_auto_action`. All dry-run-safe (verified: each primitive emits its
exact bloodyAD command under `--dry-run` and never executes).

New functions in `ad-autopwn.py`:
- `run_force_change_password(target, cfg)` — `set password` (random complex pw → `reset-creds.txt`).
- `run_add_member(group, member, cfg)` — `add groupMember` (default member = self; prints removal cmd).
- `run_write_dacl(target, cfg)` — `add genericAll` (grant self full control).
- `run_write_owner(target, cfg)` — `set owner` → `add genericAll`.
- `run_write_logon_script(target, cfg)` — `set object … scriptPath` (fallback in `_takeover_user`).
- `_takeover_user` / `_weaponize_control` — after full control, chain by type
  (Computer→RBCD, User→shadow-creds-or-logon-script, Group→add-self).
- Map additions: ForceChangePassword/AllExtendedRights (User)→reset; GenericAll/Write (User)→takeover,
  (Group)→add-self; WriteOwner/Owns and WriteDacl (User/Computer/Group)→full-control-then-chain.

Follow-up (optional, not done): WriteDACL→**DCSync** on the domain head (`bloodyAD add dcsync`) —
blocked only because the current edge extraction tags targets as User/Computer/Group, not Domain.

<details><summary>Original design notes (for reference)</summary>

We already **detect** these edges in `analyze_bloodhound_data` (`:8432`) and list them as
actionable; we just don't fire them. `bloodyAD` is already a dependency (`_bloody_auth_args`,
used at `:2738`), so each is a one-command primitive.

**New primitives** (mirror `run_shadow_credentials`'s shape):

| Technique | New fn | bloodyAD command (through `run()`) |
|---|---|---|
| Force Change Password | `run_force_change_password(target, cfg)` | `bloodyAD … set password <target> <NewPass>` |
| Add Member to Group | `run_add_member(group, member, cfg)` | `bloodyAD … add groupMember <group> <member>` |
| WriteOwner / Ownership | `run_write_owner(target, cfg)` | `bloodyAD … set owner <target> <us>` → then GenericAll |
| WriteDACL | `run_write_dacl(target, cfg)` | `bloodyAD … add genericAll <target> <us>` (or `add dcsync` on the domain head) |
| Write Logon Script | `run_write_logon_script(target, cfg)` | `bloodyAD … set object <target> scriptPath -v <unc>` |

**Wiring:** extend `_BH_AUTO_ACTION_MAP` + `_bh_auto_action` (recipe C):
```
("ForceChangePassword", "User")     -> "force_change_pw"
("Owns"/"WriteOwner", "*")          -> "write_owner"
("WriteDacl", "*")                  -> "write_dacl"
("AddMember", "Group")              -> "add_member"
```
Keep the existing cap (8) and de-dupe. For WriteDACL→WriteOwner→GenericAll, chain by having
`write_owner` fall through to `write_dacl` then the existing `rbcd`/`shadow_creds` arms — this
composes cleanly with what's already there.

**Add-Self-to-Group / All-Extended-Rights** are the same `bloodyAD` calls with the member being
`cfg.username`; no new tool.

</details>

---

## Milestone 3 — RODC suite  (P1, self-contained: 5 techniques)

**Goal:** new `rodc` phase, only meaningful when an RODC exists.
**Tools:** `bloodyAD`/`ldapmodify` (PRP edits), `impacket-secretsdump`, `impacket-ticketer`, impacket keylist.

- `detect_rodc(cfg) -> list[str]` — LDAP filter `(&(objectClass=computer)(primaryGroupID=521))`
  (Read-Only DCs) via `nxc ldap`/`bloodyAD get search`. Gates the whole phase.
- `_rodc_prp_add(rodc, principal, cfg)` — add target to `msDS-RevealOnDemandGroup` /
  Allowed-list. Covers **RODC PRP Control** + **RODC Credential Caching**. `bloodyAD add …`.
- `_rodc_extract_krbtgt(rodc, cfg)` — `impacket-secretsdump` against the RODC for its per-RODC
  krbtgt (`krbtgt_<n>`). Covers **RODC krbtgt Secret Extraction**.
- `_rodc_golden(cfg, krbtgt_hash, rodc_id)` — `impacket-ticketer` with the RODC krbtgt +
  KRBTGT number. Covers **RODC Golden Ticket**.
- `_rodc_keylist(cfg, ticket)` — impacket keylist attack against a writable DC using the forged
  ticket. Covers **Kerberos Key List (RODC)**.
- `run_rodc_attack(cfg) -> bool` — chains detect → PRP → cache → extract → golden → keylist.

Config: `no_rodc: bool`. Dispatch: creds required. Reuse ccache handling patterns from
`run_dollar_ticket` (`:6768`) / `rewrite_spn_in_ccache` (`:6483`). **Effort:** M.

---

## Milestone 4 — Initial-access cheap wins  — ✅ DONE (PRs #6/#7/#8)

Shipped, folded into `discover` (`run_credential_discovery`) and the `enrich` battery — no new phase.

- **Blank Password** & **Username-as-Password** — `_test_weak_credentials` (nxc `-p ''`, and the
  user list as password file with `--no-bruteforce`). On by default; `--no-weak-pw` to skip.
- **Anonymous LDAP Bind** — `_anonymous_ldap_bind` (nxc null bind + anonymous `ldapsearch` Root DSE).
- **GPP cpassword** — `gpp_password` module added to the nxc battery `runs` list + a
  `consume_nxc_findings` parser → `enrich-gpp.txt`.

---

## Milestone 5 — Enumeration/surface findings  — ✅ DONE (PR #9)

Shipped as `enumerate_access_surface`, called from `enumerate_targets` (so `--phase enum` and
full-auto both run it). Read-only; findings → `access-*.txt`.

| Finding | Command | MITRE | Status |
|---|---|---|---|
| Guest Session | `nxc smb <subnet> -u Guest -p ''` | T1135 | ✅ |
| RDP Access | `nxc rdp <subnet> <auth>` | T1021.001 | ✅ |
| WinRM / PS-Remoting | `nxc winrm <subnet> <auth>` (a real finding, not just an evil-winrm hint) | T1021.006 | ✅ |
| Readable/Writable/Full-Control Share | `nxc smb <subnet> <auth> --shares` → `_enum_share_acls` classifies ACLs | T1039/T1570 | ✅ |
| DCOM Execution | — | T1021.003 | omitted — reduces to local-admin, already surfaced by AdminTo |

---

## Milestone 6 — Trust, privileged-group privesc, CVEs, ESC17  (P2–P3, mostly detections)

- **Cross-Forest TGT Delegation** (`T1558`) — new small `trusts` phase or fold into `enum`:
  `bloodyAD get trusts` / `nxc ldap -M enum_trusts` to map trusts; capture a forwardable TGT via
  the existing unconstrained-delegation coercion plumbing (`try_dc_coercion`, `:1768`) aimed
  across the trust. **Effort:** M (execution), S (detection-only first cut).
- **DnsAdmins / Print Operators / Privileged Session Abuse** (`T1543.003`/`T1547.006`/`T1053.005`)
  — detections in the nxc battery / BloodHound analysis. DnsAdmins & PrintNightmare-style are
  destructive → follow adscan and mark **"Detected · not executed (safety)"**; emit the manual
  exploit command via `detail()`. Privileged-session abuse maps onto BloodHound `HasSession` +
  a scheduled-task primitive (`schtasks`/`nxc -M schtask`). **Effort:** S each (detect), M (session exec).
- **MS14-068** (`T1187`) & **MS17-010** (`T1210`) — detections. MS17-010:
  `("ms17-010", "smb", subnet, "ms17-010", [])` in the battery (recipe B), one line. MS14-068:
  patch-level heuristic + `impacket-goldenPac` hint. **Effort:** S.
- **AD CS ESC17** — extend `run_adcs_attack` (`:5699`) once `certipy` ships ESC17 support; today
  gate behind a certipy-version check and fall back to a detection + operator note. **Effort:** S.

---

## Milestone 7 — Certified Pre-Owned AD CS coverage  (P1–P3)

**Goal:** accurately implement the 18 offensive techniques defined in SpecterOps' *Certified
Pre-Owned* paper. Do not count a Certipy finding, a generic certificate request, or a supporting
primitive as end-to-end exploitation.

**Primary reference:** Will Schroeder and Lee Christensen, [*Certified Pre-Owned: Abusing
Active Directory Certificate Services*, v1.0.1](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf).
The report has three unnumbered front-matter pages, so a PDF viewer's page number is three
higher than the page printed in the report. The links below use PDF-viewer page numbers.

| ID | Paper section | Printed pages | PDF reference |
|---|---|---:|---|
| THEFT1 | Exporting Certificates Using the Crypto APIs | 38–40 | [PDF page 41](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf#page=41) |
| THEFT2 | User Certificate Theft via DPAPI | 40–42 | [PDF page 43](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf#page=43) |
| THEFT3 | Machine Certificate Theft via DPAPI | 42–44 | [PDF page 45](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf#page=45) |
| THEFT4 | Finding Certificate Files | 44–46 | [PDF page 47](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf#page=47) |
| THEFT5 | NTLM Credential Theft via PKINIT | 46–49 | [PDF page 49](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf#page=49) |
| PERSIST1 | Active User Credential Theft via Certificates | 49–52 | [PDF page 52](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf#page=52) |
| PERSIST2 | Machine Persistence via Certificates | 52–54 | [PDF page 55](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf#page=55) |
| PERSIST3 | Account Persistence via Certificate Renewal | 54 | [PDF page 57](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf#page=57) |
| ESC1 | Misconfigured Certificate Templates | 54–61 | [PDF page 57](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf#page=57) |
| ESC2 | Misconfigured Certificate Templates | 61–63 | [PDF page 64](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf#page=64) |
| ESC3 | Misconfigured Enrollment Agent Templates | 63–67 | [PDF page 66](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf#page=66) |
| ESC4 | Vulnerable Certificate Template Access Control | 67–70 | [PDF page 70](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf#page=70) |
| ESC5 | Vulnerable PKI Object Access Control | 70 | [PDF page 73](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf#page=73) |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 | 70–73 | [PDF page 73](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf#page=73) |
| ESC7 | Vulnerable Certificate Authority Access Control | 73–78 | [PDF page 76](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf#page=76) |
| ESC8 | NTLM Relay to AD CS HTTP Endpoints | 78–81 | [PDF page 81](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf#page=81) |
| DPERSIST1 | Forging Certificates with Stolen CA Certificates | 82–89 | [PDF page 85](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf#page=85) |
| DPERSIST2 | Trusting Rogue CA Certificates | 89–90 | [PDF page 92](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf#page=92) |
| DPERSIST3 | Malicious Misconfiguration | 90–91 | [PDF page 93](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf#page=93) |

### Audited baseline

| Status | Technique IDs | Current state |
|---|---|---|
| ✅ Implemented | THEFT5, ESC1, ESC4, ESC6, ESC8 | PKINIT-to-NT-hash, direct SAN abuse, template modify/exploit/restore, CA-wide SAN abuse, and HTTP enrollment relay have dedicated paths. |
| 🟡 Partial | THEFT2, ESC2, ESC3, ESC5, ESC7 | Supporting code or detection exists, but the paper's complete attack chain is not implemented. |
| ❌ Missing | THEFT1, THEFT3, THEFT4, PERSIST1–3, DPERSIST1–3 | No dedicated end-to-end workflow. |

The README's current “ESC1–ESC16 exploitation” wording must be narrowed until each ID has a
technique-specific executor and a passing live-lab test. Detection-only findings must remain
labelled as such.

### 7A — Complete the partial implementations  (P1)

- **THEFT2 — user certificate theft via DPAPI.** `run_dpapi_backup` only retrieves the domain
  DPAPI backup key. Add `run_user_certificate_theft(host, cfg)` using SharpDPAPI/DonPAPI to
  enumerate user certificate stores, recover the matching DPAPI masterkey and private key, and
  export a PFX. Record the source user, thumbprint, EKUs, expiry, and output path. Feed recovered
  authentication certificates into `_adcs_auth_pfx` without replacing `cfg` credentials until
  identity verification succeeds.
- **ESC2 — Any Purpose / no-EKU template.** Remove ESC2 from the ESC1-style `-upn
  administrator` branch. First request the Any Purpose or SubCA certificate as the caller. For an
  Any Purpose certificate, locate a compatible enrollment-agent target template and perform the
  second `certipy req -pfx <agent.pfx> -on-behalf-of <DOMAIN\\Administrator>` request. Treat a
  SubCA certificate as a separate signing/trust case and never report domain escalation merely
  because the first PFX was issued.
- **ESC3 — enrollment agent.** Implement the required two-template chain: request the
  Certificate Request Agent PFX, select a template marked as an ESC3 target, request on behalf of
  the chosen principal with `-pfx` + `-on-behalf-of`, then authenticate the resulting PFX. Add
  explicit output fields for the agent template and target template so they cannot be conflated.
- **ESC5 — vulnerable PKI object ACLs.** Preserve detection, but parse each controlled object's
  type and right into a concrete dispatcher: CA computer → existing RBCD/S4U takeover;
  certificate template → ESC4; CA/Enrollment Services object → ESC7; NTAuth/RootCA container →
  DPERSIST2. Unsupported object/right pairs remain “detected, manual action required” rather than
  falling through to a generic certificate request.
- **ESC7 — CA permissions.** Enumerate ManageCA and ManageCertificates separately. For
  ManageCA, add the caller as an officer before enabling SubCA, requesting, issuing, and
  retrieving the certificate. For ManageCertificates-only access, act only on an eligible pending
  request. Journal whether officer membership or SubCA publication already existed and remove
  only changes made by this run, including failure paths.

### 7B — Add the missing certificate-theft workflows  (P2)

- **THEFT1 — CryptoAPI/CNG export.** Add an opt-in `cert-theft` phase that inventories
  `CurrentUser\\My` and `LocalMachine\\My`, filters authentication-capable certificates, and
  exports keys through the Windows certificate APIs. Keep CAPI/CNG patching for non-exportable
  keys behind an additional high-risk flag because it tampers with cryptographic processes or
  LSASS. Retrieve exported PFX files and delete only the temporary remote files created by the
  run.
- **THEFT3 — machine certificate theft via DPAPI.** With local-admin/SYSTEM access, invoke
  SharpDPAPI `certificates /machine` (or an equivalent tested collector), recover DPAPI_SYSTEM,
  pair machine-store certificates with private keys, and export PFX files. Verify the recovered
  certificate maps to the expected computer account before offering PKINIT/S4U follow-on.
- **THEFT4 — certificate file triage.** Extend `run_loot` to search scoped shares and user/server
  directories for `.pfx`, `.p12`, `.pkcs12`, `.pem`, `.key`, `.crt`, `.cer`, `.jks`, `.keystore`,
  and `.keys`. Download candidates, fingerprint and inspect EKUs locally, run `pfx2john`/John only
  when password cracking is enabled, and deduplicate by certificate thumbprint. Never classify a
  certificate-only file as usable unless its private key is also available.

### 7C — Add explicit account-persistence workflows  (P2)

Create a standalone, opt-in `adcs-persist` phase; do not run it from `full`. Add
`--persist-technique {user,machine,renew}`, `--pfx`, `--pfx-password`, `--cert-template`, and
`--cert-principal` options.

- **PERSIST1 — user certificate enrollment.** Enumerate published authentication templates the
  current user can enroll in, request a certificate as that user (without an alternate admin SAN),
  verify the mapped identity through PKINIT, and save issuer/serial/not-before/not-after metadata.
- **PERSIST2 — machine certificate enrollment.** Require an explicit computer principal and its
  authenticated machine context or credentials. Request from a machine-authentication template,
  verify the computer identity, then reuse the existing S4U2Self path only when the operator asks
  for validation.
- **PERSIST3 — renewal.** Load an existing PFX, validate its issuer, identity, validity, and renewal
  window, then call `certipy req -pfx <old.pfx> -renew`. Preserve both old and renewed artifacts
  and verify that the renewed certificate maps to the same principal.

### 7D — Add explicit domain-persistence workflows  (P3, high impact)

These techniques require `--allow-domain-persistence`, a single explicitly selected technique,
and a named target principal. They must never be auto-fired by BloodHound or `full`.

- **DPERSIST1 — stolen CA key / forged certificate.** Add CA-certificate discovery and backup
  using Certipy CA backup or the THEFT3 machine-DPAPI path, verify the private key matches the
  enterprise CA certificate, then forge a leaf certificate with `certipy forge`/ForgeCert. Require
  explicit UPN and SID, verify the chain and mapped identity, and keep CA key material in a
  permission-restricted output directory.
- **DPERSIST2 — rogue trusted CA.** Generate an offline CA and leaf certificate, snapshot the
  exact multivalued `NTAuthCertificates` and RootCA attributes, publish only the new CA values,
  and verify Schannel/PKINIT separately. Register cleanup that removes certificates by exact DER
  value rather than restoring a stale whole-object snapshot.
- **DPERSIST3 — malicious AD CS configuration.** Support one minimal reversible persistence
  primitive first: grant a controlled principal a specific right on a named certificate template,
  or change one named template flag. Save the original security descriptor/configuration before
  mutation, provide an immediate rollback command, and prove byte-for-byte restoration in the
  lab before expanding to additional PKI objects.

### Milestone 7 acceptance tests

- Unit-test command construction, Certipy/collector output parsing, identity mapping, and artifact
  metadata without network access. A generic successful return code is never sufficient.
- Build isolated AD CS lab fixtures for every ID: two-template ESC3, split ManageCA/officer ESC7,
  exportable/non-exportable user and machine keys, renewal windows, a software-protected CA key,
  and disposable NTAuth/template objects.
- For every mutating technique, capture before/after state and force failures after each mutation
  to prove cleanup. Tests must assert that pre-existing rights, officer membership, and published
  templates are not removed.
- Mark a technique ✅ only after the complete chain produces the expected mapped principal in a
  live lab. Certificate issuance alone is partial coverage.

---

## Cross-cutting concerns

- **Dry-run safety is mandatory.** Because everything routes through `run()`, honoring
  `--dry-run` is free — *provided you never call `subprocess` directly and never write to the
  directory outside a guard*. New destructive steps (RODC PRP edits, ACL rewrites, MSSQL CLR)
  must, like ESC4/RBCD/ghost-SPN, register cleanup and respect `cfg.no_cleanup` (`:2530`,
  `_cleanup_ghost_spn` `:6883` are the templates).
- **Findings/reporting.** adscan's differentiator is its report. Consider a structured
  `cfg.findings: list[dict]` (technique, MITRE id, status, evidence path) accumulated by each
  phase and dumped as JSON in `print_summary` — cheap now, and the basis for any future
  MITRE-mapped report. Add the field to `Config` and append from each new primitive.
- **Coverage doc.** Mirror adscan: keep a `COVERAGE.md` in-repo and update it per technique so
  the README's "25+" claim tracks reality. Each milestone PR updates it.
- **Optional-dep gating.** New tools (`MSSQLPwner`, newer `certipy`) must go through
  `tool_exists()` / `find_tool()` and degrade to an operator hint when absent — never hard-fail
  a full-auto run.

## Testing strategy

- **`--dry-run` first** on every new phase — assert the emitted command lines are correct before
  any live fire (this is how the repo already validates L2 paths per the README's "Needs more
  testing" section).
- **GOAD / GOAD-Light on AWS** provides the existing cloud/routed-network baseline (README
  "Tested against"). It ships multiple DCs and remains useful for validating functionality that
  does not require Layer-2 access.
- **GOAD on the Proxmox cluster** is the second live test environment and the preferred lab for
  Layer-2 paths that AWS cannot expose (ARP, WPAD/LLMNR, DHCPv6, WSUS, and PXE). Before each
  test, confirm that the attacker VM and targets share the intended bridge/VLAN and that the
  exact topology is isolated from production networks.
- Use the Proxmox GOAD deployment for RODC (M3) and forest-trust (M6) validation when those roles
  are present. If the current topology lacks an RODC or multi-forest trust, add an isolated test
  role/topology rather than treating an untestable path as verified. Record which environment,
  GOAD variant, network segment, and topology were used in the PR or test report.
- Unit-test the pure parsers (priv-enum output, trust enumeration, share-ACL classification) the
  way `_parse_netntlmv1` / `_parse_gmsa_hashes` are structured — no network needed.

## Suggested sequence & effort

| Order | Milestone | Effort | Why here |
|---|---|---|---|
| ✅ | **M2 — Weaponize ACL edges** | S | Done in v4.13.0 (PR #5). |
| ✅ | **M4 — Initial-access wins** | S | Done (PRs #6/#7/#8). |
| ✅ | **M5 — Surface findings** | S–M | Done (PR #9). |
| ❌ | **M1 — MSSQL suite** | — | Descoped (owner decision). |
| 1 | **M3 — RODC suite** | M | Self-contained; validate on Proxmox GOAD with an RODC role. |
| 2 | **M7A — Complete partial AD CS paths** | M | Correct overstated coverage before adding more techniques. |
| 3 | **M7B/M7C — Certificate theft + account persistence** | M–L | Reuse the corrected PFX inventory/authentication pipeline. |
| 4 | **M6 — Trust / groups / CVEs / ESC17** | S–M | Mostly detections; finish the long tail. |
| 5 | **M7D — Domain persistence** | L | High-impact work; implement only after rollback tests exist. |

M2/M4/M5 are shipped and merged. Remaining: **M3 (RODC)**, **M6 (long tail)**, and
**M7 (Certified Pre-Owned AD CS completion)**.
