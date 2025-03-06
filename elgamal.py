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

        # If we get 0, the parties are in the same cell
        # (g^0 = 1 after decryption)
        if same_cell_value == 0:
            return {"same_cell": True}
        else:
            return {"same_cell": False}

    def encrypt(self, public_key, message, ephemeral_private=None):
        """
        Encrypt a message using exponential ElGamal with homomorphic properties

        Args:
            public_key: Recipient's public key
            message: Integer message to encrypt
            ephemeral_private: Optional ephemeral private key for reuse

        Returns:
            ciphertext: Dictionary with ciphertext components
        """
        if not isinstance(message, int):
            raise ValueError("Message must be an integer")

        # Generate ephemeral key pair if not provided
        if ephemeral_private is None:
            ephemeral_private = ec.generate_private_key(self.curve)

        # Extract required values from keys
        # Note: This is a simplified implementation
        # In production, you'd need proper EC point operations
        r = int.from_bytes(ephemeral_private.private_numbers().private_value.to_bytes(32, 'big'), 'big')
        A = int.from_bytes(public_key.public_numbers().x.to_bytes(32, 'big'), 'big')

        # Compute ciphertext components
        c1 = pow(g, r, self.prime_modulus)  # g^r mod p
        c2 = (pow(A, r, self.prime_modulus) * pow(g, message,
                                                  self.prime_modulus)) % self.prime_modulus  # A^r * g^m mod p

        # Store ephemeral key for serialization
        ephemeral_public = ephemeral_private.public_key()
        ephemeral_public_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return {
            "ephemeral": ephemeral_public_bytes,
            "c1": c1,
            "c2": c2
        }

    def decrypt(self, private_key, ciphertext):
        """
        Decrypt a ciphertext using exponential ElGamal

        Args:
            private_key: Recipient's private key
            ciphertext: Dictionary with ciphertext components

        Returns:
            message: Decrypted integer message
        """
        c1 = ciphertext["c1"]
        c2 = ciphertext["c2"]

        # Extract private key value
        a = int.from_bytes(private_key.private_numbers().private_value.to_bytes(32, 'big'), 'big')

        # Compute g^m = c2 / c1^a mod p
        c1_a = pow(c1, a, self.prime_modulus)
        c1_a_inv = pow(c1_a, -1, self.prime_modulus)
        g_m = (c2 * c1_a_inv) % self.prime_modulus

        # Check if g^m equals 1 (which means m = 0)
        if g_m == 1:
            return 0

        # For non-zero values, we'd need to solve the discrete log
        # For our purposes, we just need to know if it's 0 or not
        return 1  # Non-zero value

    def homomorphic_add(self, ciphertext1, ciphertext2):
        """
        Add two ciphertexts homomorphically

        Args:
            ciphertext1, ciphertext2: Ciphertexts to add

        Returns:
            ciphertext: Resulting ciphertext
        """
        # Multiply c1 components (g^r1 * g^r2 = g^(r1+r2))
        c1 = (ciphertext1["c1"] * ciphertext2["c1"]) % self.prime_modulus

        # Multiply c2 components ((A^r1 * g^m1) * (A^r2 * g^m2) = A^(r1+r2) * g^(m1+m2))
        c2 = (ciphertext1["c2"] * ciphertext2["c2"]) % self.prime_modulus

        return {
            "ephemeral": ciphertext1["ephemeral"],  # Keep track of one of the ephemeral keys
            "c1": c1,
            "c2": c2
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
        # Raise both components to the scalar power
        c1 = pow(ciphertext["c1"], scalar, self.prime_modulus)
        c2 = pow(ciphertext["c2"], scalar, self.prime_modulus)

        return {
            "ephemeral": ciphertext["ephemeral"],
            "c1": c1,
            "c2": c2
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
        # Check if we have the expected keys
        if not serialized or "ephemeral" not in serialized or "value" not in serialized:
            print(f"Invalid serialized data: {serialized}")
            # Return a default empty structure or raise a more specific exception
            return {
                "ephemeral": b"",
                "value": 0
            }

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
    try:
        if not serialized_key:
            print("Empty serialized key received")
            return None

        public_bytes = b64decode(serialized_key)
        return serialization.load_pem_public_key(public_bytes)
    except Exception as e:
        print(f"Error deserializing public key: {e}")
        # Instead of returning None, we should try to recover
        try:
            # Try with stricter error handling
            public_bytes = b64decode(serialized_key.strip())
            return serialization.load_pem_public_key(public_bytes)
        except Exception:
            return None