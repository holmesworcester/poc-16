"""Crypto: hashing, Ed25519 signatures, invite secretbox, grant sealed box."""
import hashlib
from nacl import bindings, public, secret, signing


def h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def keypair():
    sk = signing.SigningKey.generate()
    return sk, sk.verify_key.encode().hex()


def load_sk(seed_hex: str):
    return signing.SigningKey(bytes.fromhex(seed_hex))


def sign(sk, msg: str) -> str:
    return sk.sign(msg.encode()).signature.hex()


def verify(pk_hex: str, msg: str, sig_hex: str) -> bool:
    try:
        signing.VerifyKey(bytes.fromhex(pk_hex)).verify(msg.encode(), bytes.fromhex(sig_hex))
        return True
    except Exception:
        return False


def kdf(seed: bytes, tag: str) -> bytes:
    return hashlib.sha256(seed + b"/" + tag.encode()).digest()


def box_encrypt(key: bytes, b: bytes) -> bytes:
    return bytes(secret.SecretBox(key).encrypt(b))


def box_decrypt(key: bytes, b: bytes) -> bytes:
    return secret.SecretBox(key).decrypt(b)


def seal_to(ed_pk_hex: str, b: bytes) -> bytes:
    curve = bindings.crypto_sign_ed25519_pk_to_curve25519(bytes.fromhex(ed_pk_hex))
    return bytes(public.SealedBox(public.PublicKey(curve)).encrypt(b))


def unseal(sk, b: bytes) -> bytes:
    ed_sk = sk.encode() + sk.verify_key.encode()  # libsodium 64-byte form: seed || pk
    curve = bindings.crypto_sign_ed25519_sk_to_curve25519(ed_sk)
    return public.SealedBox(public.PrivateKey(curve)).decrypt(b)
