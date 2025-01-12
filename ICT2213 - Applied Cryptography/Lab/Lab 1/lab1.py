import sys
from collections import Counter

def decrypt_shift(ciphertext: str, shift: int) -> str:
    """
    Decrypt a shift cipher with the given shift value.
    
    Args:
        ciphertext (str): The encrypted text
        shift (int): The shift value to decrypt with
        
    Returns:
        str: The decrypted text
    """
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            # Convert to 0-25 range, apply shift, and convert back to ASCII
            ascii_offset = ord('A')
            shifted = (ord(char) - ascii_offset - shift) % 26
            plaintext += chr(shifted + ascii_offset)
        else:
            plaintext += char
    return plaintext

def analyze_text(text: str) -> dict:
    """
    Perform frequency analysis on the text.
    
    Args:
        text (str): The text to analyze
        
    Returns:
        dict: Character frequencies
    """
    return Counter(char for char in text if char.isalpha())

def find_likely_shift(ciphertext: str) -> int:
    """
    Find the most likely shift value by looking for common English words.
    
    Args:
        ciphertext (str): The encrypted text
        
    Returns:
        int: Most likely shift value
    """
    common_words = ['THE', 'AND', 'THAT', 'FOR']
    
    # Try each possible shift
    for shift in range(26):
        decrypted = decrypt_shift(ciphertext, shift)
        # Check if any common English words appear in the decrypted text
        if any(word in decrypted for word in common_words):
            return shift
            
    # If no shift seems likely, return None
    return None

def main():
    # Check if file is provided as argument
    if len(sys.argv) != 2:
        print("Usage: python shift_cipher_solver.py <ciphertext_file>")
        sys.exit(1)
        
    # Read ciphertext from file
    try:
        with open(sys.argv[1], 'r') as file:
            ciphertext = file.read().strip().upper()
    except FileNotFoundError:
        print(f"Error: File {sys.argv[1]} not found")
        sys.exit(1)
    
    # Find the likely shift value
    shift = find_likely_shift(ciphertext)
    if shift is not None:
        plaintext = decrypt_shift(ciphertext, shift)
        print(f"\nFound likely shift value: {shift}")
        print("\nDecrypted plaintext:")
        print(plaintext)
    else:
        print("Could not determine likely shift value automatically.")
        print("Try manual decryption with different shift values.")

if __name__ == "__main__":
    main()