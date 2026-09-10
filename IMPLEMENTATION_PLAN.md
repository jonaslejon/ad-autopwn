# Implementation Plan — Closing the adscan Feature Gap

Companion to [`TODO.md`](./TODO.md). That file lists *what* is missing; this file is *how* to
build it, grounded in ad-autopwn's actual architecture. Line references are to `ad-autopwn.py`
as of this writing (v4.12.0, ~9,780 lines).

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
- **GOAD / GOAD-Light** on AWS is the existing lab (README "Tested against"). It ships MSSQL
  (`sql.north.sevenkingdoms.local`) and multiple DCs → M1 (MSSQL) and M2 (ACL edges) are fully
  testable there. RODC (M3) and forest trusts (M6) may need **full GOAD** (not Light) or a
  nested-virt lab; note that in the PR like the existing "Needs more testing" section.
- Unit-test the pure parsers (priv-enum output, trust enumeration, share-ACL classification) the
  way `_parse_netntlmv1` / `_parse_gmsa_hashes` are structured — no network needed.

## Suggested sequence & effort

| Order | Milestone | Effort | Why here |
|---|---|---|---|
| ✅ | **M2 — Weaponize ACL edges** | S | Done in v4.13.0 (PR #5). |
| ✅ | **M4 — Initial-access wins** | S | Done (PRs #6/#7/#8). |
| ✅ | **M5 — Surface findings** | S–M | Done (PR #9). |
| ❌ | **M1 — MSSQL suite** | — | Descoped (owner decision). |
| 1 | **M3 — RODC suite** | M | Self-contained; needs full-GOAD to validate. |
| 2 | **M6 — Trust / groups / CVEs / ESC17** | S–M | Mostly detections; finish the long tail. |

M2/M4/M5 are shipped and merged. Remaining: **M3 (RODC)** and **M6 (long tail)**.
