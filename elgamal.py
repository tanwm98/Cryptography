from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import random
import json
from base64 import b64encode, b64decode


class PierreProtocol:
    """
    Implementation of the Pierre Protocol for private proximity detection

    This protocol allows two parties to determine if they are in the same grid cell
    without revealing their exact locations to each other.
    """

    def __init__(self, resolution=1000):
        """
        Initialize the Pierre Protocol

        Args:
            resolution: The size of each grid cell (default 1000)
        """
        self.resolution = resolution
        self.curve = ec.SECP256K1()
        self.prime_modulus = 2 ** 256 - 2 ** 32 - 977  # SECP256K1 prime field modulus

    def coordinates_to_cell(self, x, y):
        """
        Convert exact coordinates to grid cell coordinates

        Args:
            x: The x coordinate
            y: The y coordinate

        Returns:
            (cell_x, cell_y): The grid cell coordinates
        """
        cell_x = x // self.resolution
        cell_y = y // self.resolution
        return cell_x, cell_y

    def generate_keypair(self):
        """
        Generate an EC key pair for the protocol

        Returns:
            (public_key, private_key): The key pair
        """
        private_key = ec.generate_private_key(self.curve)
        public_key = private_key.public_key()
        return public_key, private_key

    def prepare_request(self, x, y, public_key, private_key):
        """
        Prepare a proximity request as Alice (the requester)

        Args:
            x, y: Alice's coordinates
            public_key: Alice's public key
            private_key: Alice's private key

        Returns:
            request_data: Encrypted values needed for the protocol
        """
        # Convert to grid coordinates
        x_r, y_r = self.coordinates_to_cell(x, y)

        # Calculate the values to encrypt
        xr_squared_plus_yr_squared = x_r ** 2 + y_r ** 2
        two_xr = 2 * x_r
        two_yr = 2 * y_r

        # Encrypt these values using same ephemeral key
        ephemeral_private = ec.generate_private_key(self.curve)
        encrypted_xr_squared_plus_yr_squared = self.encrypt(public_key, xr_squared_plus_yr_squared, ephemeral_private)
        encrypted_2xr = self.encrypt(public_key, two_xr, ephemeral_private)
        encrypted_2yr = self.encrypt(public_key, two_yr, ephemeral_private)

        # Create serializable request data
        request_data = {
            "resolution": self.resolution,
            "encrypted_values": {
                "xr_squared_plus_yr_squared": self.serialize_encrypted(encrypted_xr_squared_plus_yr_squared),
                "two_xr": self.serialize_encrypted(encrypted_2xr),
                "two_yr": self.serialize_encrypted(encrypted_2yr)
            }
        }

        return request_data, private_key

    def process_request(self, x, y, request_data, public_key):
        """
        Process a proximity request as Bob (the responder)

        Args:
            x, y: Bob's coordinates
            request_data: The request data from Alice
            public_key: Alice's public key

        Returns:
            response_data: The encrypted response
        """
        # Extract request parameters
        resolution = request_data.get("resolution", self.resolution)
        encrypted_values = request_data.get("encrypted_values", {})

        # Deserialize encrypted values
        encrypted_xr_squared_plus_yr_squared = self.deserialize_encrypted(
            encrypted_values.get("xr_squared_plus_yr_squared", {}))
        encrypted_2xr = self.deserialize_encrypted(
            encrypted_values.get("two_xr", {}))
        encrypted_2yr = self.deserialize_encrypted(
            encrypted_values.get("two_yr", {}))

        # Convert Bob's coordinates to grid coordinates
        u_r, v_r = self.coordinates_to_cell(x, y)

        # Calculate Bob's squared sum
        bob_squared_sum = u_r ** 2 + v_r ** 2

        # Using homomorphic properties to compute Dr = (x_r - u_r)^2 + (y_r - v_r)^2
        # We can expand this as: (x_r^2 + y_r^2) - 2*x_r*u_r - 2*y_r*v_r + (u_r^2 + v_r^2)

        # For term -2*x_r*u_r, multiply encrypted_2xr by -u_r
        term1 = self.scalar_multiply(encrypted_2xr, -u_r)

        # For term -2*y_r*v_r, multiply encrypted_2yr by -v_r
        term2 = self.scalar_multiply(encrypted_2yr, -v_r)

        # Add first three terms: (x_r^2 + y_r^2) + (-2*x_r*u_r) + (-2*y_r*v_r)
        partial_result = self.homomorphic_add(encrypted_xr_squared_plus_yr_squared, term1)
        partial_result = self.homomorphic_add(partial_result, term2)

        # Now we need to add (u_r^2 + v_r^2)
        # Since this is a constant known to Bob, encrypt it directly
        # Use the same ephemeral key as in the request
        ephemeral_public_bytes = encrypted_xr_squared_plus_yr_squared["ephemeral"]

        # Choose random rho value for security
        rho0 = random.randint(1, self.prime_modulus - 1)

        # Compute the final distance value Dr
        # Bob doesn't have Alice's private key to decrypt, so he can't directly check if Dr = 0
        # Instead, we'll compute ρ0 * ((x_r^2 + y_r^2) - 2*x_r*u_r - 2*y_r*v_r + (u_r^2 + v_r^2))
        # If Alice and Bob are in the same cell, this will be 0
        # Otherwise, it will be a random non-zero value

        # Add Bob's squared sum directly, get Dr
        dr_value = (partial_result["value"] + bob_squared_sum) % self.prime_modulus

        # Multiply by rho0 to mask the actual distance value while preserving the zero/non-zero property
        # If Dr = 0 (same cell), then rho0 * Dr = 0
        # If Dr ≠ 0 (different cells), then rho0 * Dr is a random non-zero value
        result_value = (rho0 * dr_value) % self.prime_modulus

        # Create response
        same_cell_result = {
            "ephemeral": ephemeral_public_bytes,
            "value": result_value
        }

        # Serialize the response for transmission
        response_data = {
            "same_cell": self.serialize_encrypted(same_cell_result)
        }

        return response_data

    def check_response(self, response_data, private_key):
        """
        Check the proximity response as Alice (the requester)

        Args:
            response_data: The response data from Bob
            private_key: Alice's private key

        Returns:
            proximity_result: Dictionary with proximity results
        """
        # Deserialize the response
        same_cell = self.deserialize_encrypted(response_data.get("same_cell", {}))

        # Decrypt the same_cell result
        same_cell_value = self.decrypt(private_key, same_cell)

        # Determine proximity
        # If same_cell_value = 0, they are in the same cell
        if same_cell_value == 0:
            return {"same_cell": True}
        else:
            return {"same_cell": False}

    def encrypt(self, public_key, message, ephemeral_private=None):
        """
        Encrypt a message using EC ElGamal with homomorphic properties

        Args:
            public_key: Recipient's public key
            message: Integer message to encrypt
            ephemeral_private: Optional ephemeral private key for reuse

        Returns:
            ciphertext: Dictionary with ephemeral key and encrypted value
        """
        if not isinstance(message, int):
            raise ValueError("Message must be an integer")

        # Generate ephemeral key pair if not provided
        if ephemeral_private is None:
            ephemeral_private = ec.generate_private_key(self.curve)
        ephemeral_public = ephemeral_private.public_key()

        # Derive shared secret
        shared_secret = ephemeral_private.exchange(ec.ECDH(), public_key)

        # Derive encryption key
        encryption_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'pierre-protocol-encryption',
        ).derive(shared_secret)

        # Convert to integer mask
        mask = int.from_bytes(encryption_key[:32], byteorder='big')

        # Encrypt message (additive homomorphism)
        encrypted_value = (message + mask) % self.prime_modulus

        # Serialize ephemeral public key
        ephemeral_public_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return {
            "ephemeral": ephemeral_public_bytes,
            "value": encrypted_value
        }

    def decrypt(self, private_key, ciphertext):
        """
        Decrypt a ciphertext

        Args:
            private_key: Recipient's private key
            ciphertext: Dictionary with ephemeral key and encrypted value

        Returns:
            message: Decrypted integer message
        """
        ephemeral_public_bytes = ciphertext["ephemeral"]
        encrypted_value = ciphertext["value"]

        # Load ephemeral public key
        ephemeral_public = serialization.load_pem_public_key(ephemeral_public_bytes)

        # Derive shared secret
        shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public)

        # Derive encryption key
        encryption_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'pierre-protocol-encryption',
        ).derive(shared_secret)

        # Convert to integer mask
        mask = int.from_bytes(encryption_key[:32], byteorder='big')

        # Decrypt (inverse of encryption)
        decrypted_value = (encrypted_value - mask) % self.prime_modulus

        return decrypted_value

    def homomorphic_add(self, ciphertext1, ciphertext2):
        """
        Add two ciphertexts homomorphically

        Args:
            ciphertext1, ciphertext2: Ciphertexts to add

        Returns:
            ciphertext: Resulting ciphertext
        """
        # Check that both ciphertexts use the same ephemeral key
        if ciphertext1["ephemeral"] != ciphertext2["ephemeral"]:
            raise ValueError("Homomorphic addition requires ciphertexts encrypted with the same ephemeral key")

        # Add the encrypted values modulo prime
        result_value = (ciphertext1["value"] + ciphertext2["value"]) % self.prime_modulus

        return {
            "ephemeral": ciphertext1["ephemeral"],
            "value": result_value
        }

    def scalar_multiply(self, ciphertext, scalar):
        """
        Multiply a ciphertext by a scalar homomorphically

        Args:
            ciphertext: Ciphertext to multiply
            scalar: Integer scalar

        Returns:
            ciphertext: Resulting ciphertext
        """
        # Multiply the encrypted value by the scalar modulo prime
        result_value = (ciphertext["value"] * scalar) % self.prime_modulus

        return {
            "ephemeral": ciphertext["ephemeral"],
            "value": result_value
        }

    def serialize_encrypted(self, encrypted):
        """
        Serialize encrypted values for transmission

        Args:
            encrypted: Dictionary with ephemeral key and encrypted value

        Returns:
            serialized: JSON-serializable dictionary
        """
        return {
            "ephemeral": b64encode(encrypted["ephemeral"]).decode('utf-8'),
            "value": encrypted["value"]
        }

    def deserialize_encrypted(self, serialized):
        """
        Deserialize encrypted values from transmission

        Args:
            serialized: JSON-serializable dictionary

        Returns:
            encrypted: Dictionary with ephemeral key and encrypted value
        """
        return {
            "ephemeral": b64decode(serialized["ephemeral"]),
            "value": serialized["value"]
        }


# Helper functions for integration with client/server code
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