# crypto.publickey import rsa
# crypto.random getrandombytes
# crypto cyphher pkcs1_v1_5
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from cryptography.hazmat.primitives import serialization , hashes
import sys
from math import gcd
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

def generate_private_key(n, e, p, q, d):
    private_key = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=rsa.rsa_crt_dmp1(d, p),
        dmq1=rsa.rsa_crt_dmq1(d, q),
        iqmp=rsa.rsa_crt_iqmp(p, q),
        public_numbers=rsa.RSAPublicNumbers(e=e, n=n)
    ).private_key(default_backend())

    return private_key

# Read the public key file
def read_pub_key_from_file(filename):
    try:
        with open(filename, 'rb') as key_file:
            key_data = key_file.read()
        # Load the public key
        public_key = serialization.load_pem_public_key(key_data)

        # Get the modulus and exponent
        modulus = public_key.public_numbers().n
        exponent = public_key.public_numbers().e
        print(f"{filename:<15}:")
        print(f"Modulus :\n{modulus}" )
        print(f"Exponent :\n{exponent}" )
    except Exception as e:
        print(e)
        exit(1)
    return (modulus,exponent)

def calculate_private_exponent(e, p, q):
    phi = (p - 1) * (q - 1)
    d_float = pow(e, -1)
    d_int = round(d_float)
    d = d_int % phi
    return d

def getModInverse(a, p,q):
    m = (p - 1) * (q - 1)
    #we can only find the modular inverse x = e^-1 (mod y) if gcd(x,y) == 1
    # d = a^-1 (mod m)
    if gcd(a, m) != 1:
        return None 
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m

    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (
            u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Usage : python3 corsair.py <pubCert1>.pem <pubCert2>.pem <msg1>.bin <msg2.bin>")
        exit(1)
    (n1,e1) = read_pub_key_from_file(sys.argv[1])
    (n2,e2) = read_pub_key_from_file(sys.argv[2])
    cipherMsg1 = sys.argv[3]
    cipherMsg2 = sys.argv[4]
    modulus_gcd = gcd(n1,n2)
    if modulus_gcd != 1:
        print(f"Found a prime in common : {modulus_gcd}") 
    else:
        print("Couldn't find a prime in common ! Unable to decrypt any message.")
        exit(1)
    p1 = p2 = modulus_gcd
    q1 = n1 // p1
    q2 = n2 // p2
    # d1 = calculate_private_exponent(e, p1, q1)
    # d2 = calculate_private_exponent(e, p2, q2)
    d1 = getModInverse(e1,p1,q1)
    d2 = getModInverse(e2,p2,q2)

    print("Private Exponent (d1):", d1)
    print("Private Exponent (d2):", d2)
    # Construct a Private key from the (n1,e1,d1,p1,q1)
    rsa_components1 = (n1,e1,d1,p1,q1)
    private_key1 = RSA.construct(rsa_components1, consistency_check=True)
    print(private_key1)
    # Construct a Private key from the (n2,e2,d2,p2,q2)
    rsa_components2 = (n2,e2,d2,p2,q2)
    private_key2 = RSA.construct(rsa_components2, consistency_check=True)
    print(private_key2)

    #  Crypto.Cipher.PKCS1_v1_5.new(key, randfunc=None)
    with open(cipherMsg1,"br") as file:
        ciphertext = file.read()
    cipher = PKCS1_v1_5.new(private_key1)
    decryptedMsg = cipher.decrypt(ciphertext,sentinel=0,expected_pt_len=0)
    print(decryptedMsg)
    with open(cipherMsg2,"br") as file:
        ciphertext = file.read()
    cipher = PKCS1_v1_5.new(private_key2)
    decryptedMsg = cipher.decrypt(ciphertext,sentinel=0,expected_pt_len=0)
    print(decryptedMsg)