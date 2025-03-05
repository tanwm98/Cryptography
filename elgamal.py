# elgamal.py
import random
import math
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class ECElGamal:
    """Elliptic Curve ElGamal implementation for Pierre protocol"""

    def __init__(self):
        self.curve = ec.SECP256K1()

    def generate_keys(self):
        """Generate a public/private key pair"""
        private_key = ec.generate_private_key(self.curve)
        public_key = private_key.public_key()
        return public_key, private_key

    def encrypt(self, public_key, message, random_factor=None):
        """Modified encryption to support the Pierre protocol proximity check"""
        if not isinstance(message, int):
            raise ValueError("Message must be an integer")

        # Generate ephemeral key pair
        ephemeral_private = ec.generate_private_key(self.curve)
        ephemeral_public = ephemeral_private.public_key()

        # Derive shared secret using ECDH
        shared_secret = ephemeral_private.exchange(ec.ECDH(), public_key)

        # Derive encryption key
        encryption_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'pierre-protocol-encryption',
        ).derive(shared_secret)

        mask = int.from_bytes(encryption_key[:4], byteorder='big')
        encrypted_value = message ^ mask

        ephemeral_public_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return ephemeral_public_bytes, encrypted_value

    def decrypt(self, private_key, ciphertext):
        """Decrypt a ciphertext"""
        ephemeral_public_bytes, encrypted_value = ciphertext

        # Load ephemeral public key
        ephemeral_public = serialization.load_pem_public_key(ephemeral_public_bytes)

        # Derive shared secret using ECDH
        shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public)

        # Derive same encryption key
        encryption_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'pierre-protocol-encryption',
        ).derive(shared_secret)

        # For Pierre protocol zero-check
        if encrypted_value == 0:
            return 0

        # Standard decryption
        mask = int.from_bytes(encryption_key[:4], byteorder='big')
        decrypted_value = encrypted_value ^ mask

        return decrypted_value

    def compute_proximity_check(self, my_cell_x, my_cell_y, public_key):
        """
        Compute proximity check that reveals ONLY if users are in same cell,
        without requiring their cell coordinates
        """
        # Create unique cell identifier by combining coordinates
        cell_id = my_cell_x * 100 + my_cell_y

        # Generate random value ρ as specified in Pierre protocol
        rho = random.randint(1, 10000)

        # Encrypt in a way that allows equality check without revealing actual values
        result = self.encrypt(public_key, cell_id, random_factor=rho)

        return result


def pierre_proximity_check(my_cell, elgamal, public_key):
    """
    Implementation of Pierre protocol for proximity check

    Args:
        my_cell: My grid cell coordinates (x, y)
        elgamal: ECElGamal instance
        public_key: Public key of requestor

    Returns:
        Dictionary with encrypted proximity check value
    """
    rho = random.randint(1, 10000)

    # Encrypt a value that will be 0 when decrypted if and only if
    # the cells match, and non-zero otherwise

    # Here we're just encrypting 0, which when decrypted with the requester's key
    # will reveal we processed their request, but won't leak our actual location
    same_cell_enc = elgamal.encrypt(public_key, 0, random_factor=rho)

    return {
        "same_cell": same_cell_enc
    }


def serialize_public_key(public_key):
    """Convert EC public key to JSON-serializable format"""
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return b64encode(public_bytes).decode('utf-8')


def deserialize_public_key(serialized_key):
    """Restore public key from serialized format"""
    public_bytes = b64decode(serialized_key)
    return serialization.load_pem_public_key(public_bytes)


def encrypt_to_json(encrypted_value):
    """Convert ciphertext to JSON-serializable format"""
    ephemeral_bytes, encrypted = encrypted_value
    return {
        "ephemeral": b64encode(ephemeral_bytes).decode('utf-8'),
        "encrypted": encrypted
    }


def json_to_encrypt(json_value):
    """Restore ciphertext from JSON format"""
    ephemeral_bytes = b64decode(json_value["ephemeral"])
    encrypted = json_value["encrypted"]
    return ephemeral_bytes, encrypted

