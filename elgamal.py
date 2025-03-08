from base64 import b64encode, b64decode
from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point, INFINITY
import secrets
import json


class PierreProtocol:
    """
    Implementation of the Pierre Protocol for private proximity detection
    using EC ElGamal homomorphic encryption.
    """

    def __init__(self, resolution=1000):
        """
        Initialize the Pierre Protocol

        Args:
            resolution: The size of each grid cell (default 1000)
        """
        self.resolution = resolution
        self.curve = SECP256k1
        self.G = self.curve.generator  # Generator point
        self.n = self.curve.order  # Order of the group

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
        Encrypt a message using exponential EC ElGamal.

        Args:
            public_key: Recipient's public key (Point)
            message: Integer message to encrypt. (0 is encoded as the identity)
            ephemeral_r: Optional random scalar.

        Returns:
            (c1, c2): Tuple of Points representing the ciphertext.
        """
        if ephemeral_r is None:
            ephemeral_r = secrets.randbelow(self.n - 1) + 1

        # Compute c1 = r * G
        c1 = ephemeral_r * self.G

        # Encode message as m * G; for m == 0, we use the identity point
        message_point = INFINITY if message == 0 else message * self.G

        # Compute c2 = r * public_key + message_point
        c2 = ephemeral_r * public_key + message_point

        return c1, c2

    def decrypt(self, private_key, ciphertext):
        """
        Decrypt a ciphertext using exponential EC ElGamal.

        Args:
            private_key: Recipient's private key (scalar)
            ciphertext: Tuple of Points (c1, c2)

        Returns:
            0 if decryption yields the identity (i.e. m == 0),
            or a nonzero value indicator (1) if m ≠ 0.
        """
        c1, c2 = ciphertext
        # Compute m * G = c2 - a * c1
        m_point = c2 + (-(private_key * c1))
        if m_point == INFINITY:
            return 0
        else:
            return 1

    def homomorphic_add(self, ciphertext1, ciphertext2):
        """
        Add two ciphertexts homomorphically.
        """
        c1_1, c2_1 = ciphertext1
        c1_2, c2_2 = ciphertext2
        c1_sum = c1_1 + c1_2
        c2_sum = c2_1 + c2_2
        return c1_sum, c2_sum

    def scalar_multiply(self, ciphertext, scalar):
        """
        Multiply a ciphertext by a scalar.
        """
        c1, c2 = ciphertext
        return scalar * c1, scalar * c2

    def prepare_request(self, x, y, public_key, private_key):
        """
        Prepare a proximity request as Alice (the requester)
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
        Process a proximity request as Bob (the responder)
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

        # Convert Bob's coordinates to grid coordinates
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

        # Generate random values for the protocol
        rho0 = secrets.randbelow(self.n - 1) + 1

        # Compute the three responses
        same_cell = self.scalar_multiply(dr_ciphertext, rho0)

        # Create response
        response_data = {
            "same_cell": self.serialize_ciphertext(same_cell)
        }

        return response_data

    # Serialization methods from the code snippet
    def serialize_point(self, point):
        if point == INFINITY:
            return {"x": "INFINITY", "y": "INFINITY"}
        return {"x": str(point.x()), "y": str(point.y())}

    def deserialize_point(self, data):
        if data["x"] == "INFINITY":
            return INFINITY
        return Point(self.curve.curve, int(data["x"]), int(data["y"]))

    def serialize_ciphertext(self, ciphertext):
        c1, c2 = ciphertext
        return {"c1": self.serialize_point(c1), "c2": self.serialize_point(c2)}

    def deserialize_ciphertext(self, data):
        c1 = self.deserialize_point(data["c1"])
        c2 = self.deserialize_point(data["c2"])
        return c1, c2


# Helper functions for integration with client/server code
def serialize_public_key(public_key):
    """Convert EC public key to JSON-serializable format"""
    return {"x": str(public_key.x()), "y": str(public_key.y())}


def deserialize_public_key(serialized_key):
    """Restore public key from serialized format"""
    try:
        if not serialized_key:
            print("Empty serialized key received")
            return None

        x = int(serialized_key["x"])
        y = int(serialized_key["y"])
        return Point(SECP256k1.curve, x, y)

    except Exception as e:
        print(f"Error deserializing public key: {e}")
        return None