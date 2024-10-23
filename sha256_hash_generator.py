import hashlib

def generate_sha256_hash(password):
    """Generates SHA-256 hash for a given password."""
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    return sha256_hash

# Example usage
if __name__ == "__main__":
    password = "dragon"  # Replace this with your password
    hash_value = generate_sha256_hash(password)
    print(f"SHA-256 hash of '{password}': {hash_value}")
