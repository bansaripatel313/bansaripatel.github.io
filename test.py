import random

# Function to add two large numbers as strings
def add_large_numbers(num1, num2):
    return str(int(num1) + int(num2))

# Function to subtract two large numbers as strings
def subtract_large_numbers(num1, num2):
    return str(int(num1) - int(num2))

# Function to multiply two large numbers as strings
def multiply_large_numbers(num1, num2):
    return str(int(num1) * int(num2))

# Function to divide two large numbers as strings
def divide_large_numbers(dividend, divisor):
    return str(int(dividend) // int(divisor))

# Function for modular exponentiation
def modular_exponentiation(base, exp, mod):
    return str(pow(int(base), int(exp), int(mod)))

# Extended Euclidean algorithm for GCD and modular inverse
def egcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = egcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

# Function to calculate the modular inverse of e mod phi
def mod_inverse(e, phi):
    gcd, x, _ = egcd(e, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return x % phi

# Miller-Rabin primality test
def is_prime(n, k=5):
    if n <= 1 or n % 2 == 0:
        return False
    if n == 2 or n == 3:
        return True

    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# Generate a large prime number
def generate_large_prime(bits=512):
    while True:
        num = random.getrandbits(bits)
        if is_prime(num):
            return num

# RSA key generation
def generate_rsa_keys():
    p = generate_large_prime(256)  # Generate a 256-bit prime number
    q = generate_large_prime(256)  # Generate a second 256-bit prime
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537  # Common choice for e
    d = mod_inverse(e, phi)

    return (n, e), (n, d)  # Public key (n, e), Private key (n, d)

# RSA encryption: C = M^e % n
def encrypt(message, pub_key):
    n, e = pub_key
    message_int = int.from_bytes(message.encode(), 'big')
    cipher_int = pow(message_int, e, n)
    return cipher_int

# RSA decryption: M = C^d % n
def decrypt(cipher, priv_key):
    n, d = priv_key
    message_int = pow(cipher, d, n)
    decrypted_bytes = message_int.to_bytes((message_int.bit_length() + 7) // 8, 'big')
    return decrypted_bytes.decode()

# Test the RSA implementation
def test_rsa():
    print("Generating RSA keys...")
    public_key, private_key = generate_rsa_keys()
    print(f"Public Key: {public_key}")
    print(f"Private Key: {private_key}")

    message = "Hello, RSA!"
    print(f"\nOriginal Message: {message}")

    # Encrypt the message
    encrypted_message = encrypt(message, public_key)
    print(f"Encrypted Message: {encrypted_message}")

    # Decrypt the message
    decrypted_message = decrypt(encrypted_message, private_key)
    print(f"Decrypted Message: {decrypted_message}")

    assert message == decrypted_message, "Decryption failed!"
    print("Encryption and Decryption successful!")

# Run the test
if __name__ == "__main__":
    test_rsa()
