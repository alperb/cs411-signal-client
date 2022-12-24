import random
from ecpy.curves import Curve, Point
import hashlib
class Signature:
    def __init__(self, h, s):
        self.h = h
        self.s = s

    def __str__(self):
        return f"h: {self.h}, s: {self.s}"

    def __repr__(self):
        return f"h: {self.h}, s: {self.s}"

class DigSig:
    def __init__(self):
        self.curve = Curve.get_curve('secp256k1')
        self.G = self.curve.generator
        self.P = self.curve.generator
        self.n = self.curve.order
    
    def generate_keys(self):
        # 0 < sA < n - 1
        sA = random.randint(1, self.n - 1)
        QA = (sA * self.G.x, sA * self.G.y)

        # Print the key pair
        print("Private key:", sA)
        print("Public key:", QA)

        return sA, QA

    def sign(self, m: str, sA: int):
        k = random.randint(1, self.n - 2)

        Rx, Ry = (k * self.G.x, k * self.G.y)
        
        r = Rx % self.n
        h = int(hashlib.sha3_256(f"{r}{m}".encode()).hexdigest(), 16) % self.n
        s = (k + sA * h) % self.n
        signature = Signature(h, s)

        print("Signature:", signature)
        return signature


    def verify(self, m: str, signature, QA: Point):
        Vx, Vy = (signature.s * self.G.x - signature.h * QA[0], signature.s * self.G.y - signature.h * QA[1])

        v = Vx % self.n
        h_prime = int(hashlib.sha3_256(f"{v}{m}".encode()).hexdigest(), 16) % self.n

        if signature.h == h_prime:
            print("Signature is valid.")
        else:
            print("Signature is invalid.")


# Example usage
signer = DigSig()
my_private, my_public = signer.generate_keys()
signature = signer.sign("Hello World", my_private)
signer.verify("Hello World", signature, my_public)


