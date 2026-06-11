import os
import hashlib
import base64
import json
from pathlib import Path


def _derive_key(master_key: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        master_key.encode("utf-8"),
        salt,
        100_000,
        dklen=32,
    )


def _get_master_key() -> str:
    env_key = os.environ.get("ENVMGR_MASTER_KEY")
    if env_key:
        return env_key
    config_dir = Path.home() / ".envmgr"
    key_file = config_dir / ".master_key"
    if key_file.exists():
        return key_file.read_text().strip()
    config_dir.mkdir(parents=True, exist_ok=True)
    new_key = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
    key_file.write_text(new_key)
    try:
        os.chmod(key_file, 0o600)
    except OSError:
        pass
    return new_key


def encrypt_value(plaintext: str) -> str:
    master_key = _get_master_key()
    salt = os.urandom(16)
    key = _derive_key(master_key, salt)
    data = plaintext.encode("utf-8")
    cipher = bytearray()
    for i, byte in enumerate(data):
        cipher.append(byte ^ key[i % len(key)])
    iv = os.urandom(8)
    payload = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(bytes(cipher)).decode("ascii"),
    }
    return "enc:" + base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")


def decrypt_value(encrypted: str) -> str:
    if not encrypted.startswith("enc:"):
        return encrypted
    master_key = _get_master_key()
    payload_str = base64.b64decode(encrypted[4:]).decode("utf-8")
    payload = json.loads(payload_str)
    salt = base64.b64decode(payload["salt"])
    ciphertext = base64.b64decode(payload["ciphertext"])
    key = _derive_key(master_key, salt)
    plain = bytearray()
    for i, byte in enumerate(ciphertext):
        plain.append(byte ^ key[i % len(key)])
    return bytes(plain).decode("utf-8")


def is_encrypted(value: str) -> bool:
    return isinstance(value, str) and value.startswith("enc:")


def mask_value(value: str, secret: bool = False) -> str:
    if not secret:
        return value
    if not value:
        return ""
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]
