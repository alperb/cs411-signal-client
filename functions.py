from Crypto import Random
import math


def generate_private_key(curve):
    k = Random.new().read(int(math.log(curve.order, 2)))
    k = int.from_bytes(k, byteorder='big') % curve.order
    return k

def generate_public_key(private_key, generator):
    return private_key * generator