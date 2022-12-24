import random
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256
from Crypto import Random
import math
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
        self.P = self.curve.generator
        self.n = self.curve.order
    
    def generate_keys(self):
        k = Random.new().read(int(math.log(self.n, 2)))
        sA = int.from_bytes(k, byteorder='big') % self.n
        QA = sA * self.P
        print(f"Private key sA: {sA}")
        print(f"Public key QA: {QA}")
        return sA, QA

    def sign(self, m: int, sA: int):
        k = random.randint(1, self.n - 2)

        R_ = ((k * self.P))
        r = R_.x % self.n
        m = m.to_bytes((m.bit_length()+7)//8, byteorder='big')
        h = int.from_bytes(SHA3_256.new(r.to_bytes((r.bit_length()+7)//8, byteorder='big')+m).digest(), byteorder='big')%self.n
        s = (sA*h + k) % self.n

        signature = Signature(h, s)

        return signature


    def verify(self, m: str, signature, QA: Point):
        Vx = (signature.s * self.P) - (signature.h * QA)
        v = Vx.x % self.n
        m = m.to_bytes((m.bit_length()+7)//8, byteorder='big')
        h_prime = int.from_bytes(SHA3_256.new(v.to_bytes((v.bit_length()+7)//8, byteorder='big')+m).digest(), byteorder='big')%self.n

        if signature.h == h_prime:
            print("Signature is valid.")
        else:
            print("Signature is invalid.")





