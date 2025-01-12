import sys
from collections import Counter
from math import gcd
from functools import reduce
from typing import List, Dict, Tuple

class VigenereSolver:
    def __init__(self):
        # Standard English letter frequencies
        self.ENGLISH_FREQS = {
            'A': 0.082, 'B': 0.015, 'C': 0.028, 'D': 0.043, 'E': 0.127,
            'F': 0.022, 'G': 0.020, 'H': 0.061, 'I': 0.070, 'J': 0.002,
            'K': 0.008, 'L': 0.040, 'M': 0.024, 'N': 0.067, 'O': 0.075,
            'P': 0.019, 'Q': 0.001, 'R': 0.060, 'S': 0.063, 'T': 0.091,
            'U': 0.028, 'V': 0.010, 'W': 0.024, 'X': 0.002, 'Y': 0.020,
            'Z': 0.001
        }

    def get_ic(self, text: str) -> float:
        """
        Calculate the Index of Coincidence for the text.
        """
        N = len(text)
        if N <= 1:
            return 0
            
        freqs = Counter(text)
        sum_freqs = sum(n * (n-1) for n in freqs.values())
        ic = sum_freqs / (N * (N-1))
        return ic

    def get_key_length_candidates(self, ciphertext: str, max_length: int = 20) -> List[int]:
        """
        Find possible key lengths using Index of Coincidence.
        Returns list of likely key lengths sorted by probability.
        """
        candidates = []
        # Expected IC for English text is around 0.067
        ENGLISH_IC = 0.067
        IC_THRESHOLD = 0.06  # Minimum IC to consider valid
        
        for length in range(3, min(len(ciphertext)//2, max_length + 1)):
            # Split text into columns
            columns = [''.join(ciphertext[i::length]) for i in range(length)]
            
            # Calculate average IC for this key length
            avg_ic = sum(self.get_ic(col) for col in columns) / length
            
            if avg_ic > IC_THRESHOLD:
                # Store length and how close its IC is to English
                candidates.append((length, abs(ENGLISH_IC - avg_ic)))
        
        # Sort by closest to English IC
        candidates.sort(key=lambda x: x[1])
        return [length for length, _ in candidates]

    def get_shift_score(self, text: str) -> float:
        """
        Score how well letter frequencies match English frequencies.
        Lower score is better.
        """
        length = len(text)
        freqs = Counter(text)
        score = 0
        
        for char, expected_freq in self.ENGLISH_FREQS.items():
            observed_freq = freqs.get(char, 0) / length
            score += abs(observed_freq - expected_freq)
            
        return score

    def find_key_char(self, column: str) -> str:
        """
        Find most likely key character for a column using frequency analysis.
        """
        best_score = float('inf')
        best_shift = 0
        
        for shift in range(26):
            # Try this shift
            shifted = ''.join(
                chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
                for c in column
            )
            score = self.get_shift_score(shifted)
            
            if score < best_score:
                best_score = score
                best_shift = shift
                
        return chr(best_shift + ord('A'))

    def find_key(self, ciphertext: str, key_length: int) -> str:
        """Find the most likely key of given length."""
        key = ""
        
        # Split ciphertext into columns
        for i in range(key_length):
            column = ciphertext[i::key_length]
            key += self.find_key_char(column)
            
        return key

    def decrypt(self, ciphertext: str, key: str) -> str:
        """Decrypt ciphertext using the provided key."""
        plaintext = ""
        key_len = len(key)
        
        for i, char in enumerate(ciphertext):
            if char.isalpha():
                # Convert to 0-25 range
                plain = (ord(char) - ord('A') - 
                        (ord(key[i % key_len]) - ord('A'))) % 26
                plaintext += chr(plain + ord('A'))
            else:
                plaintext += char
                
        return plaintext

    def solve(self, ciphertext: str) -> Tuple[str, str, List[int]]:
        """
        Solve the Vigenère cipher.
        Returns (key, plaintext, candidate_key_lengths)
        """
        # Clean the ciphertext
        cleaned_text = ''.join(c.upper() for c in ciphertext if c.isalpha())
        
        # Find candidate key lengths
        key_lengths = self.get_key_length_candidates(cleaned_text)
        if not key_lengths:
            raise ValueError("Could not determine likely key length")
            
        # Try the most likely key length first
        key_length = key_lengths[0]
        key = self.find_key(cleaned_text, key_length)
        plaintext = self.decrypt(cleaned_text, key)
        
        return key, plaintext, key_lengths

def main():
    if len(sys.argv) != 2:
        print("Usage: python vigenere_solver.py <ciphertext_file>")
        sys.exit(1)

    try:
        # Read ciphertext
        with open(sys.argv[1], 'r') as f:
            ciphertext = f.read().strip()
        
        # Create solver and decrypt
        solver = VigenereSolver()
        key, plaintext, key_lengths = solver.solve(ciphertext)
        
        # Print results
        print("\nPossible key lengths:", key_lengths)
        print("Found key:", key)
        print("\nDecrypted plaintext:")
        print(plaintext)
        
        # Print extra details for verification
        print("\nPlaintext statistics:")
        print(f"Length: {len(plaintext)} characters")
        print(f"Index of Coincidence: {solver.get_ic(plaintext):.3f}")
        
    except FileNotFoundError:
        print(f"Error: File {sys.argv[1]} not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()