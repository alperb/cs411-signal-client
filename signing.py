import random
from ecpy.curves import Curve, Point
import hashlib

#
# UYARI
# Buralari full chatgpt yazdi
# calismiyor buranin duzenlenmesi lazim



def generate_keys(P: Point, n: int):
    # Choose a random secret key "sA"
    # 0 < sA < n - 1
    sA = random.randint(1, n - 1)

    # Compute the public key "QA"
    QA = sA ** P

    # Print the key pair
    print("Private key:", sA)
    print("Public key:", QA)

    return sA, QA

def sign(m: str, sA: int, P: Point, n: int):
    # Choose a random integer "k" in the range "1 to n-2"
    k = random.randint(1, n - 2)

    # Compute "R" as "k * P"
    R = k * P

    # Compute "r" as the x coordinate of "R" modulo "n"
    r = R % n

    # Compute the SHA3 256 hash of the concatenation of "r" and "m" modulo "n"
    h = int(hashlib.sha3_256(f"{r}{m}".encode()).hexdigest(), 16) % n

    # Compute "s" as "k + sA * h" modulo "n"
    s = (k + (sA * h)) % n

    # The digital signature for the message "m" is the tuple "(h, s)"
    signature = (h, s)

    # Print the digital signature
    print("Signature:", signature)
    return signature


def verify(m: str, signature, QA: Point, P: Point, n: int):
    # Extract "h" and "s" from the digital signature
    s, h = signature

    # Compute "V" as "s * P - h * QA"
    V = (s * P) - (h * QA)

    # Compute "v" as the x coordinate of "V" modulo "n"
    v = V % n

    # Compute "h'" as the SHA3 256 hash of the concatenation of "v" and "m" modulo "n"
    h_prime = int(hashlib.sha3_256(f"{v}{m}".encode()).hexdigest(), 16) % n
    print("h':", h_prime)
    print("h:", h)
    # Check if "h" is equal to "h'"
    if h == h_prime:
        # If "h" is equal to "h'", then accept the signature
        print("Signature is valid")
        return True
    else:
        # If "h" is not equal to "h'", then reject the signature
        print("Signature is not valid")
        return False

curve = Curve.get_curve('secp256k1')
G = curve.generator

my_private = 107104542227582715350394877807653332933585776856568810683552776731542755971707
my_public = (0xb981136258b66a37a3a15a5bc3a09586a7ba58721cfb4fbc4d4500687a1312fe, 0xbc26b9dd785d764246f29128f693e1bf1d15b3d513fdc285f62589cf7d3ef576)

signature = sign("Hello World", my_private, my_public, curve.order)
verify("Hello World", signature, my_public, my_public, curve.order)
