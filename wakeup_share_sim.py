#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import re
import secrets
import struct
import sys
import time
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import quote_plus

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates


MAGIC = "8&%d*"
SIGN_A_KEY = "@fG2SuLA"
KEY_SALT = "@#AIjd83#@6B"

IP = [
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
    56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
]
FP = [
    39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24,
]
E = [
    31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8,
    7, 8, 9, 10, 11, 12, 11, 12, 13, 14, 15, 16,
    15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24,
    23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0,
]
P = [
    15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9,
    1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24,
]
PC1 = [
    56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17,
    9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35,
    62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
    13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3,
]
PC2 = [
    13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9,
    22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1,
    40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 46,
    43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31,
]
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
SBOX = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
]


def md5_hex(s):
    if isinstance(s, str):
        s = s.encode("utf-8")
    return hashlib.md5(s).hexdigest()


def md5_upper(s):
    return md5_hex(s).upper()


def b64_no_wrap(data):
    return base64.b64encode(data).decode("ascii")


def android_quote(s):
    return quote_plus(s, safe="")


def form_encode_items(items):
    return "&".join(f"{k}={android_quote(str(v))}" for k, v in items)


def cuid_from_android_id(android_id):
    return md5_upper("com.baidu" + (android_id or "")) + "|0"


def adid_checksum(md5_text):
    if not re.fullmatch(r"[0-9a-f]{32}", md5_text or ""):
        return "00000000"
    high64 = int(md5_text[:16], 16)
    low64 = int(md5_text[16:], 16)
    folded = high64 ^ low64
    high32 = (folded >> 32) & 0xFFFFFFFF
    low32 = folded & 0xFFFFFFFF
    return f"{(high32 ^ low32) & 0xFFFFFFFF:08x}"


def adid_from_android_id(android_id):
    seed = "alpha.beta" + (android_id or "")
    prefix = md5_hex(seed)
    return prefix + adid_checksum(prefix)


def make_common_params(args, manifest_info):
    params = [
        ("area", args.area),
        ("screensize", args.screensize),
        ("cuid", args.cuid),
        ("os", "android"),
        ("city", args.city),
        ("abis", args.abis),
        ("channel", args.channel),
        ("appBit", args.app_bit),
        ("vc", str(manifest_info["version_code"])),
        ("deviceId", args.device_id),
        ("token", args.public_token),
        ("adid", args.adid),
        ("province", args.province),
        ("pkgName", manifest_info["package"]),
        ("appId", args.app_id),
        ("download_type", args.download_type),
        ("vcname", manifest_info["version_name"]),
        ("sdk", str(args.sdk)),
        ("device", args.device),
        ("brand", args.brand),
        ("operatorid", args.operatorid),
    ]
    return [(k, "" if v is None else v) for k, v in params]


def read_u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def read_u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def read_len8(data, off):
    value = data[off]
    if value & 0x80:
        return ((value & 0x7F) << 8) | data[off + 1], off + 2
    return value, off + 1


def read_len16(data, off):
    value = read_u16(data, off)
    if value & 0x8000:
        return ((value & 0x7FFF) << 16) | read_u16(data, off + 2), off + 4
    return value, off + 2


def parse_string_pool(data, off):
    chunk_type = read_u16(data, off)
    if chunk_type != 0x0001:
        raise ValueError("AXML string pool not found")
    header_size = read_u16(data, off + 2)
    chunk_size = read_u32(data, off + 4)
    string_count = read_u32(data, off + 8)
    flags = read_u32(data, off + 16)
    strings_start = read_u32(data, off + 20)
    is_utf8 = bool(flags & 0x100)
    offsets = [read_u32(data, off + header_size + i * 4) for i in range(string_count)]
    strings_base = off + strings_start
    strings = []
    for item_off in offsets:
        pos = strings_base + item_off
        if is_utf8:
            _, pos = read_len8(data, pos)
            byte_len, pos = read_len8(data, pos)
            raw = data[pos:pos + byte_len]
            strings.append(raw.decode("utf-8", "replace"))
        else:
            char_len, pos = read_len16(data, pos)
            raw = data[pos:pos + char_len * 2]
            strings.append(raw.decode("utf-16le", "replace"))
    return strings, off + chunk_size


def parse_manifest_info(apk_path):
    with zipfile.ZipFile(apk_path, "r") as zf:
        data = zf.read("AndroidManifest.xml")

    if read_u16(data, 0) != 0x0003:
        raise ValueError("not an Android binary manifest")
    strings, off = parse_string_pool(data, 8)
    package_name = None
    version_name = None
    version_code = None

    while off + 8 <= len(data):
        chunk_type = read_u16(data, off)
        header_size = read_u16(data, off + 2)
        chunk_size = read_u32(data, off + 4)
        if chunk_size <= 0:
            break
        if chunk_type == 0x0102:
            tag_name_idx = read_u32(data, off + 20)
            tag_name = strings[tag_name_idx] if tag_name_idx != 0xFFFFFFFF else ""
            attr_start = read_u16(data, off + 24)
            attr_size = read_u16(data, off + 26)
            attr_count = read_u16(data, off + 28)
            attrs_off = off + header_size + attr_start
            if tag_name == "manifest":
                for i in range(attr_count):
                    aoff = attrs_off + i * attr_size
                    name_idx = read_u32(data, aoff + 4)
                    raw_idx = read_u32(data, aoff + 8)
                    data_type = data[aoff + 15]
                    typed_data = read_u32(data, aoff + 16)
                    name = strings[name_idx] if name_idx != 0xFFFFFFFF else ""
                    if raw_idx != 0xFFFFFFFF:
                        value = strings[raw_idx]
                    elif data_type in (0x10, 0x11):
                        value = typed_data
                    elif data_type == 0x03:
                        value = strings[typed_data]
                    else:
                        value = typed_data
                    if name == "package":
                        package_name = str(value)
                    elif name == "versionName":
                        version_name = str(value)
                    elif name == "versionCode":
                        version_code = int(value)
                break
        off += chunk_size

    if version_code is None:
        raise ValueError("versionCode not found in manifest")
    return {
        "package": package_name,
        "version_name": version_name,
        "version_code": version_code,
    }


def read_apk_text_entry(apk_path, name):
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            return zf.read(name).decode("utf-8", "replace").strip()
    except KeyError:
        return ""


def read_public_token(apk_path):
    token_re = re.compile(rb"1_[A-Za-z0-9]{30,80}(?![A-Za-z0-9_-])")
    candidates = []
    with zipfile.ZipFile(apk_path, "r") as zf:
        for name in zf.namelist():
            if not name.endswith(".dex"):
                continue
            for match in token_re.finditer(zf.read(name)):
                candidates.append(match.group().decode("ascii"))
    unique = sorted(set(candidates), key=lambda item: (len(item), item))
    if len(unique) == 1:
        return unique[0]
    return ""


def read_signature_chars(apk_path):
    with zipfile.ZipFile(apk_path, "r") as zf:
        cert_name = next(
            (n for n in zf.namelist() if n.upper().startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))),
            None,
        )
        if not cert_name:
            raise ValueError("META-INF/*.RSA/*.DSA/*.EC certificate block not found")
        pkcs7_data = zf.read(cert_name)
    certs = load_der_pkcs7_certificates(pkcs7_data)
    if not certs:
        raise ValueError(f"no certificate found in {cert_name}")
    cert_der = certs[0].public_bytes(serialization.Encoding.DER)
    return cert_der.hex(), cert_name


def bits_from_bytes_lsb(data):
    out = []
    for b in data:
        out.extend((b >> i) & 1 for i in range(8))
    return out


def bytes_from_bits_lsb(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for bit in range(8):
            b |= (bits[i + bit] & 1) << bit
        out.append(b)
    return bytes(out)


def permute(bits, table):
    return [bits[i] for i in table]


def rotate_left(values, n):
    return values[n:] + values[:n]


def native_des_subkeys(key):
    key_bytes = key.encode("utf-8") if isinstance(key, str) else bytes(key)
    if len(key_bytes) != 8:
        raise ValueError(f"native DES key must be 8 bytes, got {len(key_bytes)}")
    bits = permute(bits_from_bytes_lsb(key_bytes), PC1)
    left, right = bits[:28], bits[28:]
    subkeys = []
    for shift in SHIFTS:
        left = rotate_left(left, shift)
        right = rotate_left(right, shift)
        subkeys.append(permute(left + right, PC2))
    return subkeys


def native_des_f(right, subkey):
    expanded = permute(right, E)
    mixed = [a ^ b for a, b in zip(expanded, subkey)]
    s_bits = []
    for box_index in range(8):
        block = mixed[box_index * 6:(box_index + 1) * 6]
        row = block[0] * 2 + block[5]
        col = block[1] * 8 + block[2] * 4 + block[3] * 2 + block[4]
        value = SBOX[box_index][row][col]
        s_bits.extend([(value >> 3) & 1, (value >> 2) & 1, (value >> 1) & 1, value & 1])
    return permute(s_bits, P)


def native_des_block(block, subkeys):
    bits = permute(bits_from_bytes_lsb(block), IP)
    left, right = bits[:32], bits[32:]
    for subkey in subkeys:
        new_right = [a ^ b for a, b in zip(left, native_des_f(right, subkey))]
        left, right = right, new_right
    return bytes_from_bits_lsb(permute(right + left, FP))


def native_des_encrypt(plain, key):
    plain = plain.encode("utf-8") if isinstance(plain, str) else bytes(plain)
    subkeys = native_des_subkeys(key)
    padded_len = (len(plain) & ~7) + 8
    pad_len = padded_len - len(plain)
    padded = bytearray(plain + b"\x00" * pad_len)
    padded[(len(plain) & ~7) + 7] = pad_len
    return b"".join(native_des_block(bytes(padded[i:i + 8]), subkeys) for i in range(0, padded_len, 8))


def native_des_decrypt(cipher, key):
    cipher = bytes(cipher)
    if len(cipher) % 8:
        raise ValueError("native DES ciphertext length must be a multiple of 8")
    subkeys = list(reversed(native_des_subkeys(key)))
    plain = b"".join(native_des_block(cipher[i:i + 8], subkeys) for i in range(0, len(cipher), 8))
    if not plain:
        return plain
    pad_len = plain[-1]
    if pad_len > len(plain):
        raise ValueError(f"invalid native DES padding length: {pad_len}")
    return plain[:-pad_len]


def rev4(value):
    return ((value & 1) << 3) | ((value & 2) << 1) | ((value & 4) >> 1) | ((value & 8) >> 3)


def native_hex_encode(data, add_newline=False):
    parts = []
    for b in data:
        parts.append(f"{rev4(b & 0x0F):02x}{rev4((b >> 4) & 0x0F):02x}")
    text = "".join(parts)
    return text + ("\n" if add_newline else "")


def native_hex_decode(text):
    clean = text[: (len(text) // 4) * 4]
    out = bytearray()
    for i in range(0, len(clean), 4):
        low = rev4(int(clean[i + 1], 16))
        high = rev4(int(clean[i + 3], 16))
        out.append(low | (high << 4))
    return bytes(out)


def generate_rand10():
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(10))


def make_sign_a(cuid, signature_chars, rand10=None, add_newline=False):
    rand10 = rand10 or generate_rand10()
    app_sig_md5 = md5_hex(signature_chars)
    plain = f"{MAGIC}##{rand10}##{app_sig_md5}##{cuid}"
    cipher = native_des_encrypt(plain, SIGN_A_KEY)
    return native_hex_encode(cipher, add_newline=add_newline), rand10, plain


def parse_sign_a(sign_a):
    plain = native_des_decrypt(native_hex_decode(sign_a), SIGN_A_KEY).decode("utf-8", "replace")
    parts = plain.split("##", 3)
    if len(parts) != 4:
        raise ValueError(f"unexpected signA plaintext: {plain!r}")
    return {
        "magic": parts[0],
        "rand10": parts[1],
        "app_sig_md5": parts[2],
        "cuid": parts[3],
        "plain": plain,
    }


def validate_sign_a_for_native(sign_a_info, expected_app_sig_md5, expected_cuid):
    checks = {
        "magic_match": sign_a_info["magic"] == MAGIC,
        "app_sig_md5_match": sign_a_info["app_sig_md5"] == expected_app_sig_md5,
        "cuid_match": sign_a_info["cuid"] == expected_cuid,
    }
    checks["native_set_token_compatible"] = all(checks.values())
    return checks


def read_libpreference_antispam(xml_path):
    root = ET.parse(xml_path).getroot()
    values = {}
    for elem in root.iter():
        name = elem.attrib.get("name")
        if name in ("KEY_ANTISPAM_SIGN_A", "KEY_ANTISPAM_SIGN_B"):
            values[name] = elem.text or ""
    return values


def token_from_sign_b(sign_b, rand10):
    key = rand10[:5] + "#G4"
    plain = native_des_decrypt(native_hex_decode(sign_b), key)
    if len(plain) < 22:
        raise ValueError(f"unexpected signB plaintext length {len(plain)}: {plain!r}")
    if plain[:10].decode("latin1") != rand10:
        raise ValueError(f"signB rand mismatch: {plain[:10]!r} != {rand10!r}")
    return plain[12:22].decode("latin1"), plain


def native_get_key(type_str, token):
    m0 = md5_hex(KEY_SALT)
    m1 = md5_hex(type_str)
    m2 = md5_hex(f"[{token}]@")
    m2 = m2[17:32][::-1] + m2[15:17] + m2[0:15][::-1]
    chars = list(m0 + m1 + m2)
    for i in range(3):
        chars[i], chars[-1 - i] = chars[-1 - i], chars[i]
    s = "".join(chars)
    out = s + md5_hex(s)
    chars = list(out)
    left, right = 0, len(chars) - 1
    for _ in range(60):
        chars[left], chars[right] = chars[right], chars[left]
        left += 1
        right -= 1
    return "".join(chars)


def native_get_sign(base64_param_string, token):
    return md5_hex(f"{MAGIC}[{md5_hex(token)}]@{base64_param_string}")


def rc4_crypt(data, key):
    key_bytes = key.encode("utf-8") if isinstance(key, str) else bytes(key)
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key_bytes[i % len(key_bytes)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def build_antispam_request(sign_a, common_params):
    body_items = [("data", sign_a)] + common_params
    return {
        "body": form_encode_items(body_items) + "&",
        "params_for_body": body_items,
    }


def build_conf_request(token, common_params, nt="wifi", server_time=None, kakorr=None):
    server_time = int(server_time if server_time is not None else time.time())
    kakorr = int(kakorr if kakorr is not None else time.monotonic() * 1000)

    sign_list = [f"{k}={v}" for k, v in common_params]
    sign_list.extend([
        f"nt={nt}",
        f"_t_={server_time}",
        f"kakorrhaphiophobia={kakorr}",
    ])
    joined = "".join(sorted(sign_list))
    base64_param = b64_no_wrap(joined.encode("utf-8"))
    sign = native_get_sign(base64_param, token)
    sign_pack = f"{sign}&_t_={server_time}&kakorrhaphiophobia={kakorr}"
    body = form_encode_items(common_params + [("nt", nt)])
    body += f"&sign={sign_pack}"
    return {
        "sign_list": sorted(sign_list),
        "joined_sign_params": joined,
        "base64_sign_params": base64_param,
        "sign": sign,
        "body": body,
    }


def build_share_request(code, token, version_code, common_params, nt="wifi", did="", server_time=None, kakorr=None):
    type_str = str(version_code)
    rc4_key = native_get_key(type_str, token)
    plain_params = "key=" + android_quote(code)
    data_value = b64_no_wrap(rc4_crypt(plain_params.encode("utf-8"), rc4_key))
    server_time = int(server_time if server_time is not None else time.time())
    kakorr = int(kakorr if kakorr is not None else time.monotonic() * 1000)

    sign_list = [f"data={data_value}"]
    sign_list.extend(f"{k}={v}" for k, v in common_params)
    if did:
        sign_list.append(f"did={did}")
    sign_list.extend([
        f"nt={nt}",
        f"_t_={server_time}",
        f"kakorrhaphiophobia={kakorr}",
    ])
    joined = "".join(sorted(sign_list))
    base64_param = b64_no_wrap(joined.encode("utf-8"))
    sign = native_get_sign(base64_param, token)
    sign_pack = f"{sign}&_t_={server_time}&kakorrhaphiophobia={kakorr}"

    # HttpCurrencyRequest.toString() emits "?&data=...", so the real POST body
    # keeps a leading '&' after df.d strips the URL path.
    extra_params = [("did", did)] if did else []
    body = "&" + form_encode_items([("data", data_value)] + common_params + extra_params + [("nt", nt)])
    body += f"&sign={sign_pack}"
    return {
        "plain_params": plain_params,
        "rc4_key": rc4_key,
        "data": data_value,
        "sign_list": sorted(sign_list),
        "joined_sign_params": joined,
        "base64_sign_params": base64_param,
        "sign": sign,
        "body": body,
    }


def post_form(url, body, timeout, session=None, cuid="", did="", adid=""):
    client = session or requests
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Accept-Encoding": "gzip, deflate, br",
        "na__zyb_source__": "wakeup",
    }
    if cuid:
        headers["zyb-cuid"] = cuid
    if did:
        headers["zyb-did"] = did
    if adid:
        headers["zyb-adid"] = adid
    return client.post(
        url,
        data=body.encode("utf-8"),
        headers=headers,
        timeout=timeout,
    )


def response_debug(resp):
    return {
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
        "cookies": requests.utils.dict_from_cookiejar(resp.cookies),
        "text": resp.text,
    }


def decrypt_response_data(response_text, rc4_key):
    try:
        payload = json.loads(response_text)
    except json.JSONDecodeError as exc:
        return {"error": f"response is not JSON: {exc}"}

    encrypted = None
    path = None
    data = payload.get("data") if isinstance(payload, dict) else None
    if isinstance(data, dict) and isinstance(data.get("data"), str):
        encrypted = data["data"]
        path = "data.data"
    elif isinstance(data, str):
        encrypted = data
        path = "data"
    if not encrypted:
        return {"error": "encrypted response data not found", "payload": payload}

    try:
        plain_bytes = rc4_crypt(base64.b64decode(encrypted), rc4_key)
    except Exception as exc:
        return {"error": f"response decrypt failed: {exc}", "encrypted_path": path, "encrypted": encrypted}

    plain_text = plain_bytes.decode("utf-8", "replace")
    result = {
        "encrypted_path": path,
        "encrypted": encrypted,
        "plain_text": plain_text,
    }
    try:
        result["plain_json"] = json.loads(plain_text)
    except json.JSONDecodeError:
        pass
    return result


def main():
    default_apks = sorted(Path.cwd().glob("*.apk"))
    parser = argparse.ArgumentParser(description="Simulate WakeUp share-code RC4/sign request flow.")
    parser.add_argument("--apk", default=str(default_apks[0]) if default_apks else None)
    parser.add_argument("--code", help="share code to import")
    parser.add_argument("--cuid", default="", help="cuid used by nativeInitBaseUtil; real app value is best")
    parser.add_argument("--operatorid", default="", help="operatorid common parameter; real app value is best")
    parser.add_argument("--channel", default=None, help="network common parameter channel; defaults to assets/channel")
    parser.add_argument("--public-token", default=None, help="network common parameter token; defaults to the APK embedded value")
    parser.add_argument("--sdk", default=35, type=int)
    parser.add_argument("--device", default="Pixel 7")
    parser.add_argument("--brand", default="google")
    parser.add_argument("--adid", default="")
    parser.add_argument("--did", default="")
    parser.add_argument("--screensize", default="1080x2400")
    parser.add_argument("--abis", default="arm64-v8a")
    parser.add_argument("--app-bit", default="64")
    parser.add_argument("--device-id", default="")
    parser.add_argument("--download-type", default="1")
    parser.add_argument("--app-id", default="wakeup")
    parser.add_argument("--province", default="")
    parser.add_argument("--city", default="")
    parser.add_argument("--area", default="")
    parser.add_argument("--token", help="known 10-byte antispam token")
    parser.add_argument("--prefs-xml", help="exported com.baidu.homework.Preference.LibPreference.xml with cached signA/signB")
    parser.add_argument("--sign-a", help="existing signA; used to recover rand10 for --sign-b")
    parser.add_argument("--sign-b", help="existing signB returned by /pluto/app/antispam")
    parser.add_argument("--rand10", help="force rand10 when generating signA or decrypting signB")
    parser.add_argument("--send-antispam", action="store_true", help="POST signA to antispam server to obtain signB")
    parser.add_argument("--send-conf", action="store_true", help="POST /wakeup/app/conf as a simple final-sign probe")
    parser.add_argument("--send-share", action="store_true", help="POST the final share-code request")
    parser.add_argument("--antispam-host", default="https://api.wakeup.fun")
    parser.add_argument("--api-host", default="https://api.wakeup.fun")
    parser.add_argument("--nt", choices=["wifi", "mobile"], default="wifi")
    parser.add_argument("--server-time", type=int, help="override _t_ value, seconds")
    parser.add_argument("--kakorr", type=int, help="override kakorrhaphiophobia")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--signa-newline", action="store_true", help="append a newline to signA; not used by the real app")
    parser.add_argument("--no-signa-newline", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    session = requests.Session()

    if not args.apk:
        raise SystemExit("No APK path given and no *.apk found in current directory.")
    apk_path = Path(args.apk)
    info = parse_manifest_info(apk_path)
    asset_channel = read_apk_text_entry(apk_path, "assets/channel")
    if args.channel is None:
        args.channel = asset_channel
    apk_public_token = read_public_token(apk_path)
    public_token_source = "argument"
    if args.public_token is None:
        if not apk_public_token:
            raise SystemExit("Could not find the APK embedded public token; pass --public-token explicitly.")
        args.public_token = apk_public_token
        public_token_source = "apk"
    signature_chars, cert_name = read_signature_chars(apk_path)
    common_params = make_common_params(args, info)

    prefs_values = {}
    if args.prefs_xml:
        prefs_values = read_libpreference_antispam(args.prefs_xml)
        if not args.sign_a:
            args.sign_a = prefs_values.get("KEY_ANTISPAM_SIGN_A")
        if not args.sign_b:
            args.sign_b = prefs_values.get("KEY_ANTISPAM_SIGN_B")

    sign_a_info = None
    if args.sign_a:
        sign_a = args.sign_a
        sign_a_info = parse_sign_a(sign_a)
        rand10 = args.rand10 or sign_a_info["rand10"]
    else:
        sign_a, rand10, sign_a_plain = make_sign_a(
            args.cuid,
            signature_chars,
            rand10=args.rand10,
            add_newline=args.signa_newline and not args.no_signa_newline,
        )
        sign_a_info = {
            "magic": MAGIC,
            "rand10": rand10,
            "app_sig_md5": md5_hex(signature_chars),
            "cuid": args.cuid,
            "plain": sign_a_plain,
        }
    sign_a_validation = validate_sign_a_for_native(sign_a_info, md5_hex(signature_chars), args.cuid)

    sign_b = args.sign_b
    antispam_response = None
    antispam_request = build_antispam_request(sign_a, common_params)
    if args.send_antispam and not sign_b:
        antispam_url = args.antispam_host.rstrip("/") + "/pluto/app/antispam"
        resp = post_form(
            antispam_url,
            antispam_request["body"],
            args.timeout,
            session=session,
            cuid=args.cuid,
            did=args.did,
            adid=args.adid,
        )
        antispam_response = response_debug(resp)
        try:
            resp.raise_for_status()
        except requests.HTTPError as exc:
            antispam_response["http_error"] = str(exc)
        try:
            payload = resp.json()
            candidate = payload.get("data")
            if isinstance(candidate, dict):
                candidate = candidate.get("data")
            if not isinstance(candidate, str):
                result_obj = payload.get("result")
                candidate = result_obj.get("data") if isinstance(result_obj, dict) else None
            sign_b = candidate if isinstance(candidate, str) and candidate else None
        except json.JSONDecodeError:
            sign_b = None

    token = args.token
    sign_b_plain = None
    if not token and sign_b:
        token, sign_b_plain = token_from_sign_b(sign_b, rand10)

    result = {
        "apk": str(apk_path),
        "manifest": info,
        "asset_channel": asset_channel,
        "apk_public_token": apk_public_token,
        "public_token_source": public_token_source,
        "cert_entry": cert_name,
        "signature_chars_md5": md5_hex(signature_chars),
        "sign_a_plain": sign_a_info["plain"],
        "sign_a_validation": sign_a_validation,
        "sign_a": sign_a,
        "rand10": rand10,
        "antispam_url": args.antispam_host.rstrip("/") + "/pluto/app/antispam",
        "common_params": common_params,
        "antispam_request": antispam_request,
    }
    if args.prefs_xml:
        result["prefs_xml"] = str(Path(args.prefs_xml))
        result["prefs_xml_keys_found"] = sorted(prefs_values)
    if antispam_response:
        result["antispam_response"] = antispam_response
        if not sign_b:
            result["antispam_error"] = "Antispam response did not contain a JSON data field."
    if sign_b:
        result["sign_b"] = sign_b
    if sign_b_plain is not None:
        result["sign_b_plain_latin1"] = sign_b_plain.decode("latin1", "replace")
    if token:
        result["token"] = token
        result["rc4_key_for_version"] = native_get_key(str(info["version_code"]), token)
        conf = build_conf_request(
            token,
            common_params,
            nt=args.nt,
            server_time=args.server_time,
            kakorr=args.kakorr,
        )
        result["conf_url"] = args.api_host.rstrip("/") + "/wakeup/app/conf"
        result["conf"] = conf
        if args.send_conf:
            resp = post_form(
                result["conf_url"],
                conf["body"],
                args.timeout,
                session=session,
                cuid=args.cuid,
                did=args.did,
                adid=args.adid,
            )
            result["conf_response"] = response_debug(resp)

    if args.code:
        if not token:
            result["share_error"] = "Need --token, --sign-b, or --send-antispam before building share request."
        else:
            share = build_share_request(
                args.code,
                token,
                info["version_code"],
                common_params,
                nt=args.nt,
                did=args.did,
                server_time=args.server_time,
                kakorr=args.kakorr,
            )
            share_url = args.api_host.rstrip("/") + "/share_schedule/getv2"
            result["share_url"] = share_url
            result["share"] = share
            if args.send_share:
                resp = post_form(
                    share_url,
                    share["body"],
                    args.timeout,
                    session=session,
                    cuid=args.cuid,
                    did=args.did,
                    adid=args.adid,
                )
                result["share_response"] = response_debug(resp)
                result["share_response_decrypted"] = decrypt_response_data(resp.text, share["rc4_key"])
                result["session_cookies"] = requests.utils.dict_from_cookiejar(session.cookies)

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
