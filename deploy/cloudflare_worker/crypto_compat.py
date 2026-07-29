"""Workerd-compatible PyNaCl sealed-box operations."""
import os

from nacl import bindings


def _nonce(ephemeral_public, recipient_public):
    return bindings.crypto_generichash_blake2b_salt_personal(
        ephemeral_public + recipient_public,
        digest_size=bindings.crypto_box_NONCEBYTES,
    )


def seal_to(ed_pk_hex, message):
    """Produce the libsodium sealed-box wire format without libsodium EM_ASM."""
    recipient = bindings.crypto_sign_ed25519_pk_to_curve25519(
        bytes.fromhex(ed_pk_hex))
    ephemeral_public, ephemeral_secret = bindings.crypto_box_seed_keypair(
        os.urandom(bindings.crypto_box_SEEDBYTES))
    ciphertext = bindings.crypto_box(
        message,
        _nonce(ephemeral_public, recipient),
        recipient,
        ephemeral_secret,
    )
    return ephemeral_public + ciphertext


def unseal(sk, sealed):
    """Open either this implementation's or libsodium's sealed-box format."""
    ed_secret = sk.encode() + sk.verify_key.encode()
    recipient_secret = bindings.crypto_sign_ed25519_sk_to_curve25519(ed_secret)
    recipient_public = bindings.crypto_scalarmult_base(recipient_secret)
    split = bindings.crypto_box_PUBLICKEYBYTES
    ephemeral_public, ciphertext = sealed[:split], sealed[split:]
    return bindings.crypto_box_open(
        ciphertext,
        _nonce(ephemeral_public, recipient_public),
        ephemeral_public,
        recipient_secret,
    )
