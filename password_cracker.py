import hashlib
import logging
import string
from itertools import product
import pyopencl as cl  # For GPU acceleration

# Setup logging
logging.basicConfig(filename='password_cracker.log', level=logging.INFO)

def password_strength(password):
    """Evaluates the strength of a given password."""
    length = len(password)
    if length < 6:
        return "Very Weak"
    elif length < 8:
        return "Weak"
    elif length < 10:
        return "Moderate"
    elif length < 12:
        return "Strong"
    else:
        return "Very Strong"

def generate_suffixes(base, max_length):
    """Generates suffixes based on the base string, including both letters and numbers."""
    characters = string.ascii_lowercase + string.digits  # Now includes digits
    for length in range(1, max_length + 1):
        for suffix in product(characters, repeat=length):
            yield base + ''.join(suffix)

def hash_password(password, hash_type):
    """Hashes a password using the specified hash type."""
    if hash_type == 'md5':
        return hashlib.md5(password.encode()).hexdigest()
    elif hash_type == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()
    return None

def crack_password_brute_force(password_hash, hash_type):
    """Cracks password using brute force method."""
    characters = string.ascii_lowercase  # You can expand this to include uppercase, digits, symbols
    for length in range(1, 6):  # Adjust the length as needed
        for guess in product(characters, repeat=length):
            guess = ''.join(guess)
            if hash_type == "md5":
                hashed_guess = hashlib.md5(guess.encode()).hexdigest()
            elif hash_type == "sha256":
                hashed_guess = hashlib.sha256(guess.encode()).hexdigest()
            else:
                print("Unsupported hash type")
                return

            if hashed_guess == password_hash:
                print(f"[+] Password found: {guess}")
                strength = password_strength(guess)
                print(f"Password strength: {strength}")
                logging.info(f"Password found: {guess} (Strength: {strength})")
                return
    print("[-] Password not found in the wordlist.")

def crack_password_dictionary(password_hash, hash_type):
    """Cracks password using a dictionary attack."""
    with open('wordlist.txt', 'r') as wordlist:
        for word in wordlist:
            word = word.strip()
            if hash_type == "md5":
                hashed_word = hashlib.md5(word.encode()).hexdigest()
            elif hash_type == "sha256":
                hashed_word = hashlib.sha256(word.encode()).hexdigest()
            else:
                print("Unsupported hash type")
                return

            if hashed_word == password_hash:
                print(f"[+] Password found: {word}")
                strength = password_strength(word)
                print(f"Password strength: {strength}")
                logging.info(f"Password found: {word} (Strength: {strength})")
                return
    print("[-] Password not found in the wordlist.")

def crack_password_hybrid(password_hash, hash_type):
    """Cracks password using a hybrid attack (dictionary + brute force)."""
    with open('wordlist.txt', 'r') as wordlist:
        for word in wordlist:
            word = word.strip()
            # Check dictionary
            if hash_type == "md5":
                hashed_word = hashlib.md5(word.encode()).hexdigest()
            elif hash_type == "sha256":
                hashed_word = hashlib.sha256(word.encode()).hexdigest()
            else:
                print("Unsupported hash type")
                return

            if hashed_word == password_hash:
                print(f"[+] Password found: {word}")
                strength = password_strength(word)
                print(f"Password strength: {strength}")
                logging.info(f"Password found: {word} (Strength: {strength})")
                return

            # Brute force on the word with suffixes
            for guess in generate_suffixes(word, 2):  # You can adjust the maximum suffix length
                if hash_type == "md5":
                    hashed_guess = hashlib.md5(guess.encode()).hexdigest()
                elif hash_type == "sha256":
                    hashed_guess = hashlib.sha256(guess.encode()).hexdigest()

                if hashed_guess == password_hash:
                    print(f"[+] Password found (hybrid): {guess}")
                    strength = password_strength(guess)
                    print(f"Password strength: {strength}")
                    logging.info(f"Password found (hybrid): {guess} (Strength: {strength})")
                    return
    print("[-] Password not found in the wordlist.")

def crack_password_cli():
    print("This is Warrior's Vault: Password Cracker!")
    
    # Input hash type
    hash_type = input("Enter the hash type (e.g., md5, sha256): ").lower()
    
    # Input password hash to crack
    password_hash = input("Enter the password hash: ")
    
    # Choose cracking method
    print("Choose a cracking method:")
    print("1. Brute Force")
    print("2. Dictionary Attack")
    print("3. Hybrid Attack")
    method_choice = input("Enter the number of your choice: ")
    
    if method_choice == '1':
        crack_password_brute_force(password_hash, hash_type)
    elif method_choice == '2':
        crack_password_dictionary(password_hash, hash_type)
    elif method_choice == '3':
        crack_password_hybrid(password_hash, hash_type)
    else:
        print("Invalid choice. Please choose a valid method.")

def main():
    crack_password_cli()

if __name__ == "__main__":
    main()
