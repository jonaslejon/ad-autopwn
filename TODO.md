# TODO — Technique Gap vs. ADScanPro/adscan

Coverage gaps found by comparing **ad-autopwn** against **[ADScanPro/adscan](https://github.com/ADScanPro/adscan)**.
This is a to-do list of techniques adscan implements that ad-autopwn **does not** — candidates to add.

## Method / sources

- **adscan side:** its own `COVERAGE.md` (auto-generated from the product catalog),
  cloned `2026-09-10`. It advertises "105 techniques"; the generated catalog lists
  **104 techniques across 15 categories** (71 executed end-to-end, AD CS ESC1–ESC17).
  Note: `COVERAGE.md` counts *detections* and *attack-path pivots* as techniques, not
  just executed exploits — so the raw 104 is inflated relative to "things it actually runs."
- **ad-autopwn side:** verified against `ad-autopwn.py` source (not just the README) —
  grepped for each candidate primitive and the `nxc` enrichment battery module list.

**Rough scorecard:** ad-autopwn has parity-or-better on ~45 of adscan's 104 catalog entries.
The list below is what's genuinely missing plus a smaller "detected but not weaponized"
set. Because ad-autopwn is an *orchestrator*, most gaps are "wire up an existing tool"
(nxc / certipy / bloodyAD / impacket) rather than net-new protocol code.

Priority key: **P1** = high-value / commonly needed on engagements · **P2** = useful, moderate effort · **P3** = niche / detection-only parity.

> **Scope decisions**
> - **MSSQL suite — descoped** (owner decision). adscan's 10 MSSQL techniques are intentionally
>   out of scope for ad-autopwn and are not tracked here.
> - **ACL-edge weaponization — DONE** in v4.13.0 (see the section below).

---

## P1 — Read-Only Domain Controller (RODC) suite (entire family missing)

adscan has 5 RODC techniques; ad-autopwn has **none** (`rodc` = 0 hits in source).
Relevant whenever the target env has an RODC. Tooling: `impacket`, `certipy`/`bloodyAD` for PRP edits.

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

## P2 — Initial-access / pre-auth findings (missing)

- [ ] **Anonymous LDAP Bind** — detect + dump directory over an anonymous bind. `T1087.002`
- [ ] **Blank Password** — test accounts for empty passwords. `T1110.001`
- [ ] **Username as Password** — test `sAMAccountName == password` across discovered users. `T1110.003`
      (Cheap add to the existing `discover`/spray path — we already have `pre2k` + single-password spray.)
- [ ] **Group Policy Preferences (GPP) cpassword** — decrypt `cpassword` from SYSVOL Groups.xml etc.
      We currently run only `nxc -M gpp_autologin` (registry autologon), **not** GPP `cpassword` recovery. `T1552.006`

---

## P2 — Delegation / credential-access enumeration (missing or detect-only)

- [ ] **Coercion to TGT (Unconstrained Delegation)** — we *enumerate* unconstrained-delegation hosts but don't
      coerce a DC/host and capture its TGT from a controlled unconstrained-delegation machine. `T1187`
- [ ] **Shadow Credentials Present** — enumerate *existing* `msDS-KeyCredentialLink` entries (we only *write* them). `T1606.002`
- [ ] **DS-Replication rights findings** — surface `GetChanges` / `GetChanges-All` / `In-Filtered-Set` ACEs
      as discrete findings (we do DCSync, but don't report the granular replication ACEs that enable it). `T1003.006`
- [ ] **Domain Password Reuse pivot** — cluster accounts sharing recovered secrets and pivot across them. `T1078.002`

---

## P2 — Lateral-movement surface findings (missing)

We extract AdminTo hosts and do PtH reuse, but don't enumerate these access surfaces as findings:

- [ ] **RDP Access** — flag hosts where a controlled principal has interactive RDP. `T1021.001`
- [ ] **PowerShell Remoting / WinRM Access** — flag WinRM exec capability as a finding (we only *suggest* evil-winrm in output). `T1021.006`
- [ ] **DCOM Execution** — detect remote DCOM exec capability. `T1021.003`
- [ ] **Guest Session** — detect accepted guest SMB sessions. `T1135`
- [ ] **Share ACL findings** — enumerate **Readable / Writable / Full-Control shares** as first-class findings.
      We drop NTLM-theft files on writable shares but don't inventory share ACLs / hunt creds in share content. `T1039` / `T1570` / `T1552.001`

---

## P2 — Privilege escalation via privileged groups (mostly missing)

We already have **Backup Operators (DRSR)** ✅. adscan additionally covers:

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

We cover **ESC1–ESC16** via certipy, plus our unique **ESC1-CMC (KB5014754) bypass**. Missing:

- [ ] **AD CS ESC17** — adscan lists ESC1–ESC17; we top out at ESC16. Add ESC17 detection/exploit. `T1557`

---

## Not gaps — where ad-autopwn already leads adscan

For scope clarity (do **not** add these; we already have them and adscan does not):

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
- ~~**Weaponize detected ACL edges** (P1)~~ — ✅ done in v4.13.0.

Remaining:

1. **Initial-access cheap wins** (P2) — blank / username-as-password / anonymous-bind / GPP cpassword.
2. **RODC suite** (P1) — self-contained family; only matters when an RODC is present.
3. **Enumeration findings** (P2) — RDP/WinRM/DCOM/guest/share-ACL surfacing.
4. **Trust abuse, privileged-group privesc, CVE detections, ESC17** (P2–P3).
