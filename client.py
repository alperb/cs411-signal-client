from ecpy.curves import Curve
from Crypto import Random
import math

server_pk = {
    'x': 0xce1a69ecc226f9e667856ce37a44e50dbea3d58e3558078baee8fe5e017a556d,
    'y': 0x13ddaf97158206b1d80258d7f6a6880e7aaf13180e060bb1e94174e419a4a093
}

my_private = 107104542227582715350394877807653332933585776856568810683552776731542755971707
my_public = {
    'x': 0xb981136258b66a37a3a15a5bc3a09586a7ba58721cfb4fbc4d4500687a1312fe,
    'y': 0xbc26b9dd785d764246f29128f693e1bf1d15b3d513fdc285f62589cf7d3ef576,
}



curve = Curve.get_curve('secp256k1')
G = curve.generator