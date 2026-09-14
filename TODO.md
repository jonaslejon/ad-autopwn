# TODO — Project Roadmap and Technique Gaps

This file tracks prioritized work and completion status. Detailed design and
implementation notes live in [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md);
keep the two files aligned when scope or milestones change.

## Repository hardening roadmap (reviewed 2026-09-14)

Complete these in order; dependency provenance should be settled before
publishing a container image.

1. [ ] **Resolve third-party licensing and provenance.** `cmc_addext.py` comes
   from [MazX0p/cmc-addext](https://github.com/MazX0p/cmc-addext), which currently
   publishes no explicit license. Obtain redistribution permission or stop
   vendoring it and install it separately. Add `THIRD_PARTY_NOTICES.md` with the
   upstream URL, pinned commit, copyright holder, modifications, and license for
   every bundled third-party component.
2. [ ] **Prevent accidental publication of sensitive artifacts.** Expand
   `.gitignore` beyond Python caches to cover `.DS_Store`, virtual environments,
   default `ad-autopwn-*` run directories, PCAPs, PFX files, ccaches, kirbi files,
   hashes, and other generated secrets. Prefer one documented output root so the
   ignore rules remain narrow and reviewable.
3. [ ] **Add `SECURITY.md` and private vulnerability reporting.** Document the
   supported version policy, how to report unsafe behavior or exposed secrets,
   what evidence to include, and that client names, domains, credentials, hashes,
   and engagement output must be sanitized. Enable GitHub private vulnerability
   reporting instead of directing sensitive reports to public issues.
4. [ ] **Add safe CI and protect `main`.** Create a GitHub Actions workflow for
   Python compilation, `ad-autopwn.py --help`, CLI/README consistency, dependency
   imports, and unit tests for pure logic. Never contact a target or run live
   attack phases in CI. Protect `main` from deletion and force-pushes and require
   the CI check; mandatory PR reviews can wait while there is one maintainer.
5. [ ] **Add contributor/community files.** Add `CONTRIBUTING.md`,
   `CODE_OF_CONDUCT.md`, sanitized bug and feature issue forms, and a pull-request
   template. Bug reports should include version, OS, Python, phase, relevant
   external-tool versions, a minimal reproduction, and redacted output.
6. [ ] **Establish release and version discipline.** Add `--version`, make one
   source authoritative for the version, create `CHANGELOG.md`, tag releases, and
   publish GitHub releases. Start with a curated v4.13.0 release rather than
   automating an unproven release process.
7. [ ] **Make installation reproducible.** Add `pyproject.toml` with Python
   `>=3.10`, package metadata, development checks, and console entry points.
   Record exact commits/checksums for `/opt/tools` dependencies in a lock manifest
   and distinguish required, phase-specific, and optional tools.
8. [ ] **Add a scoped Docker runtime.** Build only after item 7. Start with the
   authenticated and non-L2 phases, a mounted output directory, pinned tools, and
   an image smoke test. Document Linux host networking and opt-in
   `NET_RAW`/`NET_ADMIN`/`NET_BIND_SERVICE` capabilities for L2/listener phases;
   avoid `--privileged` and explain Docker Desktop's L2 limitations.
9. [ ] **Add dependency and release automation.** Configure Dependabot for Python
   and GitHub Actions after CI exists. Add automatic release-note generation only
   after the manual changelog/tag workflow has been used successfully.
10. [ ] **Consider optional project metadata.** Add `CITATION.cff` if academic or
    research citation matters, `FUNDING.yml` if sponsorship is wanted, and a
    devcontainer only after the development/container environment is stable.

## ⚠️ Bugs found by live L2 testing (2026-09-11)

- [x] **BUG 1 (high):** backgrounded `ntlmrelayx` dies on stdin-EOF → every relay
  phase (`arp`, DC relay) captures nothing and the ARP spoof is torn down in ~2 s.
  Fix in `run()` bg branch (`ad-autopwn.py:409`): launch with `stdin=subprocess.PIPE`
  and keep the handle open (`/dev/null` = EOF, does not work). Also bump the 2 s
  settle check at `:1288`. Validated: `sleep infinity | ntlmrelayx` stays up.
- [x] **BUG 2 (med):** prereq gate (`:1001`, exit at `:9924`) hard-fails *all* phases,
  incl. `--dry-run`, when the CVE-2025-33073 PoC is absent. Make the PoC required
  per-phase, or always let `--dry-run` through. Breaks the "dry-run first" workflow.
- [x] **BUG 3 (low):** pipx tools (mitm6, coercer, wsuks, bloodyAD, sccmhunter) show
  as "not found" because `sudo` strips `~/.local/bin` from PATH. Probe `SUDO_USER`'s
  `~/.local/bin` in `tool_exists`.
- [ ] README "Needs more testing": `arp` relay now validated live on-prem — blocked
  only by BUG 1. `wsus`/`pxe` remain N/A on GOAD-Light (no WSUS/PXE services).


## Technique coverage backlog

This is a prioritized list of useful techniques that ad-autopwn does not yet
implement, plus completed work retained for historical context.

## Review method

- Coverage was verified against `ad-autopwn.py` source, rather than relying only
  on README claims, including the NetExec enrichment battery and BloodHound
  auto-action mappings.
- Detections, attack-path pivots, and executed exploits are treated as different
  levels of coverage; a detection alone is not counted as end-to-end support.

Because ad-autopwn is an orchestrator, most gaps involve integrating an existing
tool such as NetExec, Certipy, bloodyAD, or Impacket rather than implementing a
protocol from scratch.

Priority key: **P1** = high-value / commonly needed on engagements · **P2** = useful, moderate effort · **P3** = niche / detection-only parity.

> **Scope decisions**
> - **MSSQL suite — descoped** (owner decision) and not tracked here.
> - **ACL-edge weaponization — DONE** in v4.13.0 (see the section below).

---

## P1 — Read-Only Domain Controller (RODC) suite (entire family missing)

ad-autopwn currently has no RODC support (`rodc` = 0 hits in source). This suite
is relevant when the target environment contains an RODC. Tooling candidates:
Impacket, Certipy, and bloodyAD for PRP edits.

- [ ] **RODC Password Replication Policy Control** — modify the RODC's `msDS-RevealOnDemandGroup` / PRP. `T1098`
- [ ] **RODC Credential Caching** — force target creds to cache on a controlled/compromised RODC. `T1098`
- [ ] **RODC krbtgt Secret Extraction** — pull the per-RODC krbtgt secret from a compromised RODC. `T1003`
- [ ] **RODC Golden Ticket** — forge a reusable golden ticket from the per-RODC krbtgt. `T1558.001`
- [ ] **Kerberos Key List (RODC)** — use the RODC golden ticket to request Key List data from a writable DC. `T1558`

---

## P1 — Forest / trust abuse (missing)

- [ ] **Cross-Forest TGT Delegation** — capture a forwardable TGT delegated across a forest trust to escalate into the trusting forest. `T1558`
      (ad-autopwn does no trust enumeration or cross-forest attack path today.)

---

## ✅ DONE (v4.13.0) — Weaponize ACL edges the BloodHound analysis already detects

Implemented in `ad-autopwn.py` as bloodyAD-driven primitives, auto-fired by `_bh_auto_action`
(map: `_BH_AUTO_ACTION_MAP`). All dry-run-safe. Previously the auto-action chain only fired
WriteSPN, AddKeyCredentialLink, ReadGMSA, GenericAll/WriteAccountRestrictions→RBCD.

- [x] **Force Change Password** — `run_force_change_password` (bloodyAD `set password`, random pw → `reset-creds.txt`). `T1098`
- [x] **WriteDACL** — `run_write_dacl` (grant self GenericAll → chain by type). `T1222.001`
- [x] **WriteOwner / Object Ownership** — `run_write_owner` (`set owner` → GenericAll → chain). `T1222.001`
- [x] **Add Member to Group** / **Add Self to Group** — `run_add_member` (bloodyAD `add groupMember`, prints removal cmd). `T1098`
- [x] **All Extended Rights** — mapped `(AllExtendedRights, User) → force_change_pw`. `T1098`
- [x] **Write Logon Script** — `run_write_logon_script` (`set object … scriptPath`), used as `_takeover_user` fallback when shadow creds fail. `T1098`
- [x] Filled auto-action map gaps: `GenericAll/GenericWrite` on **User** → shadow-creds-or-logon-script; on **Group** → add-self.

Remaining (optional follow-up): grant **DCSync** rights via WriteDACL on the domain head
(bloodyAD `add dcsync`) — not yet wired because BloodHound `target_type` is only User/Computer/Group,
not Domain, in the current edge extraction.

---

## ✅ DONE (M4) — Initial-access / pre-auth findings

Shipped in PRs #6/#7/#8, folded into the `discover` + `enrich` batteries (no new phase).

- [x] **Anonymous LDAP Bind** — `_anonymous_ldap_bind` (nxc null bind + anonymous ldapsearch Root DSE). `T1087.002`
- [x] **Blank Password** — `_test_weak_credentials` (nxc `-p ''`). On by default (`--no-weak-pw` to skip). `T1110.001`
- [x] **Username as Password** — `_test_weak_credentials` (nxc `--no-bruteforce`, user list as password file). `T1110.003`
- [x] **Group Policy Preferences (GPP) cpassword** — `gpp_password` module added to the nxc battery + `consume_nxc_findings` parser → `enrich-gpp.txt`. `T1552.006`

---

## P2 — Delegation / credential-access enumeration (missing or detect-only)

- [ ] **Coercion to TGT (Unconstrained Delegation)** — we *enumerate* unconstrained-delegation hosts but don't
      coerce a DC/host and capture its TGT from a controlled unconstrained-delegation machine. `T1187`
- [ ] **Shadow Credentials Present** — enumerate *existing* `msDS-KeyCredentialLink` entries (we only *write* them). `T1606.002`
- [ ] **DS-Replication rights findings** — surface `GetChanges` / `GetChanges-All` / `In-Filtered-Set` ACEs
      as discrete findings (we do DCSync, but don't report the granular replication ACEs that enable it). `T1003.006`
- [ ] **Domain Password Reuse pivot** — cluster accounts sharing recovered secrets and pivot across them. `T1078.002`

---

## ✅ DONE (M5) — Lateral-movement surface findings

Shipped in PR #9 as `enumerate_access_surface`, called from `enumerate_targets` (so `--phase enum` + full-auto both run it). Findings → `access-*.txt`.

- [x] **RDP Access** — `nxc rdp` across the subnet. `T1021.001`
- [x] **PowerShell Remoting / WinRM Access** — `nxc winrm`, surfaced as a finding (not just an evil-winrm hint). `T1021.006`
- [x] **Guest Session** — `nxc smb -u Guest -p ''`. `T1135`
- [x] **Share ACL findings** — `nxc smb --shares`, classified Readable / Writable / Full-Control (`_enum_share_acls`). `T1039` / `T1570`
- [~] **DCOM Execution** — deliberately **not** probed separately: it reduces to local-admin, already surfaced by the AdminTo extraction in the BloodHound phase. `T1021.003`

---

## P2 — Privilege escalation via privileged groups (mostly missing)

We already have **Backup Operators (DRSR)**. Additional useful gaps are:

- [ ] **DnsAdmins Abuse** — DNS server DLL load → SYSTEM on the DC (detect; execution is destructive). `T1543.003`
- [ ] **Print Operators Abuse** — driver-load / SeLoadDriverPrivilege escalation path. `T1547.006`
- [ ] **Privileged Session Abuse** — high-value user session on a non-Tier-0 host → scheduled-task impersonation. `T1053.005`
- [ ] **Scheduled Task Execution (session impersonation)** — register a task under a logged-on user's session.
      (We have GPO scheduled-task-**as-SYSTEM** via pyGPOAbuse — related but not the same primitive.) `T1053.005`
- [ ] **Privileged Group Control finding** — explicit terminal-privileged-group membership finding
      (partially covered by our BloodHound high-value analysis; make it a discrete reported finding). `T1098`

---

## P3 — Known-CVE detections (parity gaps)

We already detect **Zerologon, noPac, PrintNightmare** in the enrich battery. Missing:

- [ ] **MS14-068 / Kerberos PAC Forgery** — detect/flag (impacket `goldenPac`-style). `T1187`
- [ ] **MS17-010 (EternalBlue)** — detect SMBv1 RCE exposure (`nxc smb -M ms17-010`). `T1210`

---

## P3 — AD CS

We cover **ESC1–ESC16** via Certipy, plus **ESC1-CMC (KB5014754)**. Missing:

- [ ] **AD CS ESC17** — add ESC17 detection and exploitation. `T1557`

---

## Existing strengths — not gaps

For scope clarity, these capabilities are already implemented:

- **Layer-2 / passive:** ARP spoof + relay, WPAD/mitm6, **WSUS relay**, **PXE boot cred theft**,
  **SCCM NAA theft**, WebDAV coercion, DHCP coercion, NTLM-theft file drops.
- **2026 reflection CVEs:** CVE-2025-58726 (ghost-SPN AP-REQ), CVE-2026-24294, CVE-2026-26128,
  CVE-2025-33073 fallback.
- **ESC1-CMC** KB5014754 `id-cmc-addExtensions` bypass (bundled `cmc_addext.py`).
- **Dollar Ticket**, **RBCD+KCD chain orchestrator**, **TGS sname rewrite**.
- **BadSuccessor / DMSA** (2024) via `nxc -M badsuccessor`, **ADIDNS** nonsecure zones.
- **AppLocker bypass / WSUS update injection** (wsuks), **KeePass vault crack**,
  **NetNTLMv1 → crack.sh DES** machine-hash recovery.

---

## Suggested order of attack

- ~~**MSSQL suite**~~ — descoped (owner decision).
- ~~**Weaponize detected ACL edges** (P1)~~ — ✅ done in v4.13.0 (PR #5).
- ~~**Initial-access cheap wins** (P2)~~ — ✅ done (PRs #6/#7/#8).
- ~~**Enumeration findings** (P2)~~ — ✅ done (PR #9).

Remaining:

1. **RODC suite** (P1) — self-contained family; only matters when an RODC is present. Needs full-GOAD to validate.
2. **Trust abuse, privileged-group privesc, CVE detections, ESC17** (P2–P3) — mostly detections.
