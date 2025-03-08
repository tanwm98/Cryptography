from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point, INFINITY
import secrets
import json
import time
import struct


class PierreProtocol:
    """
    Implementation of Pierre Protocol using EC ElGamal for secure proximity testing.
    """

    def __init__(self, resolution=1000, distance_threshold=2500):
        self.resolution = resolution
        self.distance_threshold = distance_threshold
        self.curve = SECP256k1
        self.G = self.curve.generator
        self.n = self.curve.order

    def coordinates_to_cell(self, x, y):
        """Convert coordinates to grid cell coordinates."""
        return x // self.resolution, y // self.resolution

    def generate_keypair(self):
        """Generate a private/public key pair."""
        private_key = secrets.randbelow(self.n - 1) + 1
        public_key = private_key * self.G  # Scalar multiplication
        return public_key, private_key

    def encrypt(self, public_key, message, ephemeral_r=None):
        """
        Encrypt a message using EC ElGamal.

        Args:
            public_key: Recipient's public key (Point)
            message: Integer message to encrypt
            ephemeral_r: Optional random scalar

        Returns:
            Tuple of Points representing the ciphertext
        """
        if ephemeral_r is None:
            ephemeral_r = secrets.randbelow(self.n - 1) + 1

        # Compute c1 = r * G
        c1 = ephemeral_r * self.G

        # Encode message as m * G
        message_point = message * self.G

        # Compute c2 = r * public_key + message_point
        c2 = ephemeral_r * public_key + message_point

        return c1, c2

    def decrypt(self, private_key, ciphertext, max_value=5):
        """
        Decrypt a ciphertext for small values using brute force.

        Args:
            private_key: Recipient's private key (scalar)
            ciphertext: Tuple of Points (c1, c2)
            max_value: Maximum expected value to check

        Returns:
            The decrypted message, or None if not found
        """
        c1, c2 = ciphertext
        # Compute shared secret s = private_key * c1
        shared_secret = private_key * c1
        # Compute m * G = c2 - shared_secret
        m_point = c2 + (-shared_secret)

        # For small values like 0, 1, 2 (needed for the Pierre protocol)
        # we can efficiently check if it's 0
        if m_point == INFINITY:
            return 0

        # For the Pierre protocol, we're primarily interested in whether the result is zero
        # For more robust implementation, we can also check small values directly
        # Compare m_point with i*G for i in range(max_value)
        for i in range(1, max_value + 1):
            if i * self.G == m_point:
                return i

        # If the point doesn't match any of our expected small values,
        # return a non-zero value to indicate "not in same cell"
        return 999  # Large value to indicate not the same cell

    def is_zero(self, private_key, ciphertext):
        """Debug version of is_zero with more information"""
        c1, c2 = ciphertext
        # Compute shared secret s = private_key * c1
        shared_secret = private_key * c1
        # Calculate m_point = c2 - shared_secret
        m_point = c2 + (-shared_secret)

        print(f"Debug is_zero:")
        print(f"  c1: {c1}")
        print(f"  c2: {c2}")
        print(f"  shared_secret: {shared_secret}")
        print(f"  m_point: {m_point}")
        print(f"  infinity check: {m_point == INFINITY}")
        print(f"  c2 == shared_secret: {c2 == shared_secret}")

        return c2 == shared_secret

    def homomorphic_add(self, ciphertext1, ciphertext2):
        """
        Add two ciphertexts homomorphically.

        Args:
            ciphertext1, ciphertext2: Encrypted values

        Returns:
            Encryption of the sum
        """
        c1_1, c2_1 = ciphertext1
        c1_2, c2_2 = ciphertext2
        c1_sum = c1_1 + c1_2
        c2_sum = c2_1 + c2_2
        return c1_sum, c2_sum

    def scalar_multiply(self, ciphertext, scalar):
        """
        Multiply a ciphertext by a scalar.

        Args:
            ciphertext: Encrypted value
            scalar: Integer to multiply by

        Returns:
            Encryption of the product
        """
        c1, c2 = ciphertext
        return scalar * c1, scalar * c2

    def prepare_request(self, x, y, public_key, private_key):
        """
        Prepare a proximity request

        Args:
            x, y: Requester's coordinates
            public_key: Requester's public key
            private_key: Requester's private key (stored for later use)

        Returns:
            request_data: Dictionary with encrypted values
        """
        # Convert to grid coordinates
        x_r, y_r = self.coordinates_to_cell(x, y)

        # Calculate the values to encrypt
        xr_squared_plus_yr_squared = x_r ** 2 + y_r ** 2
        two_xr = 2 * x_r
        two_yr = 2 * y_r

        # Encrypt these values
        encrypted_xr_squared_plus_yr_squared = self.encrypt(public_key, xr_squared_plus_yr_squared)
        encrypted_2xr = self.encrypt(public_key, two_xr)
        encrypted_2yr = self.encrypt(public_key, two_yr)

        # Create request data
        request_data = {
            "resolution": self.resolution,
            "encrypted_values": {
                "xr_squared_plus_yr_squared": self.serialize_ciphertext(encrypted_xr_squared_plus_yr_squared),
                "two_xr": self.serialize_ciphertext(encrypted_2xr),
                "two_yr": self.serialize_ciphertext(encrypted_2yr)
            }
        }

        return request_data, private_key

    def process_request(self, u, v, request_data, requester_public_key):
        """
        Process a proximity request

        Args:
            u, v: Responder's coordinates
            request_data: Dictionary with encrypted values
            requester_public_key: Requester's public key

        Returns:
            response_data: Dictionary with proximity test results
        """
        # Extract request parameters
        encrypted_values = request_data.get("encrypted_values", {})

        # Deserialize encrypted values
        encrypted_xr_squared_plus_yr_squared = self.deserialize_ciphertext(
            encrypted_values.get("xr_squared_plus_yr_squared", {}))
        encrypted_2xr = self.deserialize_ciphertext(
            encrypted_values.get("two_xr", {}))
        encrypted_2yr = self.deserialize_ciphertext(
            encrypted_values.get("two_yr", {}))

        # Convert responder's coordinates to grid coordinates
        u_r, v_r = self.coordinates_to_cell(u, v)

        # Calculate terms for distance calculation
        term1 = self.scalar_multiply(encrypted_2xr, -u_r)  # -2*x_r*u_r
        term2 = self.scalar_multiply(encrypted_2yr, -v_r)  # -2*y_r*v_r

        # Add first three terms
        partial_sum = self.homomorphic_add(encrypted_xr_squared_plus_yr_squared, term1)
        partial_sum = self.homomorphic_add(partial_sum, term2)

        # Encrypt Bob's squared sum and add it
        bob_term = self.encrypt(requester_public_key, u_r ** 2 + v_r ** 2)
        dr_ciphertext = self.homomorphic_add(partial_sum, bob_term)

        # At this point, dr_ciphertext encrypts (x_r - u_r)² + (y_r - v_r)² = D_r

        # Generate random non-zero values as specified in the Pierre protocol
        rho0 = secrets.randbelow(self.n - 2) + 1  # range [1, n-1]
        rho1 = secrets.randbelow(self.n - 2) + 1
        rho2 = secrets.randbelow(self.n - 2) + 1
        rho_threshold = secrets.randbelow(self.n - 2) + 1
        # Prepare the three tests:
        # 1. Same cell: D_r = 0
        same_cell = self.scalar_multiply(dr_ciphertext, rho0)

        # 2. Adjacent cell: D_r = 1
        # We need to create E(D_r - 1) = E(D_r) + E(-1)
        minus_one = self.encrypt(requester_public_key, -1)
        dr_minus_one = self.homomorphic_add(dr_ciphertext, minus_one)
        adjacent_cell = self.scalar_multiply(dr_minus_one, rho1)
        threshold_squared = (self.distance_threshold / self.resolution) ** 2
        # Create E(D_r - threshold_squared)
        minus_threshold = self.encrypt(requester_public_key, -threshold_squared)
        dr_minus_threshold = self.homomorphic_add(dr_ciphertext, minus_threshold)
        euclidean_test = self.scalar_multiply(dr_minus_threshold, rho_threshold)
        # 3. Diagonally adjacent: D_r = 2
        # We need to create E(D_r - 2) = E(D_r) + E(-2)
        minus_two = self.encrypt(requester_public_key, -2)
        dr_minus_two = self.homomorphic_add(dr_ciphertext, minus_two)
        diagonal_cell = self.scalar_multiply(dr_minus_two, rho2)

        # Create response with all three tests
        response_data = {
            "same_cell": self.serialize_ciphertext(same_cell),
            "adjacent_cell": self.serialize_ciphertext(adjacent_cell),
            "diagonal_cell": self.serialize_ciphertext(diagonal_cell),
            "euclidean_test": self.serialize_ciphertext(euclidean_test),
            "threshold": self.distance_threshold  # Include the threshold for reference
        }

        return response_data

    # Serialization methods
    def serialize_point(self, point):
        """Convert EC point to serializable format"""
        if point == INFINITY:
            return {"x": "INFINITY", "y": "INFINITY"}
        return {"x": str(point.x()), "y": str(point.y())}

    def deserialize_point(self, data):
        """Convert serialized format back to EC point"""
        if data.get("x") == "INFINITY":
            return INFINITY
        return Point(self.curve.curve, int(data["x"]), int(data["y"]))

    def serialize_ciphertext(self, ciphertext):
        """Convert ciphertext to serializable format"""
        c1, c2 = ciphertext
        return {"c1": self.serialize_point(c1), "c2": self.serialize_point(c2)}

    def deserialize_ciphertext(self, data):
        """Convert serialized format back to ciphertext"""
        c1 = self.deserialize_point(data["c1"])
        c2 = self.deserialize_point(data["c2"])
        return c1, c2


# Helper functions for integration with client.py

def serialize_public_key(public_key):
    """Convert EC public key to JSON-serializable format"""
    if public_key is None:
        return None
    return {"x": str(public_key.x()), "y": str(public_key.y())}


def deserialize_public_key(serialized_key):
    """Restore public key from serialized format"""
    try:
        if not serialized_key or "x" not in serialized_key:
            return None
        x = int(serialized_key["x"])
        y = int(serialized_key["y"])
        return Point(SECP256k1.curve, x, y)
    except Exception as e:
        print(f"Error deserializing public key: {e}")
        return None