import random
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
from Crypto import Random
import math
import requests
import json

API_URL = 'http://10.92.55.4:5000'

class Keys(object):
    def __init__(self, public, private):
        self.public = public
        self.private = private

    def __str__(self):
        return f"<Keys => public: {self.public}, private: {self.private}>"

class Signature:
    def __init__(self, h, s):
        self.h = h
        self.s = s

    def __str__(self):
        return f"<Signature => h: {self.h}, s: {self.s}>"

# DigitalSignature
# Handles the signing and verification of messages
# Also generates key pairs
class DigitalSignature:
    def __init__(self):
        self.curve = Curve.get_curve('secp256k1')
        self.generator = self.curve.generator
        self.order = self.curve.order
    
    def generate_keys(self):
        k = Random.new().read(int(math.log(self.order, 2)))
        private = int.from_bytes(k, byteorder='big') % self.order
        public = private * self.generator

        return Keys(public, private)

    def sign(self, m: int, sA: int):
        k = random.randint(1, self.order - 2)

        R_ = ((k * self.generator))
        r = R_.x % self.order
        m = self.__to_bytes(m)
        h = int.from_bytes(SHA3_256.new(self.__to_bytes(r) + m).digest(), byteorder='big') % self.order
        s = (sA*h + k) % self.order

        return Signature(h, s)

    def verify(self, m: str, signature: Signature, QA: Point):
        Vx = (signature.s * self.generator) - (signature.h * QA)
        v = Vx.x % self.order
        m = self.__to_bytes(m)
        h_prime = int.from_bytes(SHA3_256.new(self.__to_bytes(v) + m).digest(), byteorder='big') % self.order

        if signature.h == h_prime:
            print("Signature is valid.")
            return True
        else:
            print("Signature is invalid.")
            return False

    def __to_bytes(self, n):
        return n.to_bytes((n.bit_length()+7)//8, byteorder='big')

class SignalClient(object):
    def __init__(self, student_id: int, keys: dict[str, str]):
        self.student_id = student_id
        self.digital_signature = DigitalSignature()
        self.keys = {
            'private': keys['private'],
            'public': Point(keys['public']['x'], keys['public']['y'], self.digital_signature.curve, True)
        }

        self.server_public = Point(
            0xce1a69ecc226f9e667856ce37a44e50dbea3d58e3558078baee8fe5e017a556d, 
            0x13ddaf97158206b1d80258d7f6a6880e7aaf13180e060bb1e94174e419a4a093, 
            Curve.get_curve('secp256k1'),
            True
        )

        self.presigned_keys = self.digital_signature.generate_keys()
    
    def start(self):
        self.register_identity()
        self.verify_server_code()
        self.register_presigned_keys()
        self.verify_spk_from_server()
        self.generate_otk()

    def register_presigned_keys(self):
        concatted = int.from_bytes(
            self.__to_bytes(self.presigned_keys.public.x) + 
            self.__to_bytes(self.presigned_keys.public.y)
        , byteorder='big')

        spk_sign = self.digital_signature.sign(concatted, self.keys['private'])
        self.digital_signature.verify(concatted, spk_sign, self.keys['public'])

        res = self.__send_presigned_signature(spk_sign)
        if res[0]:
            print("Successfully registered presigned keys.")
            self.server_spk = res[1]
            #res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']
        else:
            print("Failed to register presigned keys.")
            print(f"Error: {res[1]}")

    def verify_server_code(self):
        self.code = int(input("\nEnter the code sent to your email: "))
        res = self.__verify_email_code()

        if res:
            print("Successfully verified email code.")
            print(f"Server response: {res[1]}")
        else:
            print("Failed to verify email code.")
            print(f"Error: {res[1]}")
    
    def register_identity(self):
        print(f"Signing student id ({self.student_id})...")
        signature = self.digital_signature.sign(self.student_id, self.keys['private'])
        print(f"Signature: {signature}")

        print(f"Verifying signature...")
        self.digital_signature.verify(self.student_id, signature, self.keys['public'])

        print(f"Sending signature to server...")
        result = self.__send_identity_to_server(signature)
        if result[0]:
            print("Successfully registered identity.")
            print(f"Server response: {result[1]}")
        else:
            print("Failed to register identity.")
            print(f"Error: {result[1]}")

    def verify_spk_from_server(self):
        concatted = int.from_bytes(
            self.__to_bytes(self.server_spk['SPKPUB.X']) + 
            self.__to_bytes(self.server_spk['SPKPUB.Y'])
        , byteorder='big')   

        signature = Signature(self.server_spk['H'], self.server_spk['S'])
        r = self.digital_signature.verify(concatted, signature, self.server_public)
        if r:
            print("Successfully verified server presigned key.")
        else:
            print("Failed to verify server presigned key.")
    
    def generate_otk(self):
        temp_s_point = Point(self.server_spk['SPKPUB.X'], self.server_spk['SPKPUB.Y'], self.digital_signature.curve, True)
        T = (self.presigned_keys.private * temp_s_point)
        U = b'CuriosityIsTheHMACKeyToCreativity' + T.y.to_bytes((T.y.bit_length()+7)//8, byteorder='big') + T.x.to_bytes((T.x.bit_length()+7)//8, byteorder='big')
        K = SHA3_256.new(U).digest()

        self.otk = {
            'privates': [],
            'public': [],
            'hmac': []
        }

        for i in range(0, 10):
            keys = self.digital_signature.generate_keys()
            self.otk['privates'].append(keys.private)
            self.otk['public'].append(keys.public)
            concatted = self.__to_bytes(keys.public.x) + self.__to_bytes(keys.public.y)

            hmac_i = HMAC.new(K, concatted, digestmod=SHA256).hexdigest()
            self.otk['hmac'].append(hmac_i)
        
        self.__register_one_time_keys()
        self.save_otks()
    
    # Helper functions

    def __to_bytes(self, n):
        return n.to_bytes(32, byteorder='big')

    def save_otks(self):
        with open('otk.json', 'w') as f:
            jsonized = {
                'privates': [],
                'public': []
            }
            for i in range(len(self.otk['privates'])):
                jsonized['privates'].append(self.otk['privates'][i].to_bytes(32, byteorder='big').hex())
                jsonized['public'].append({
                    'X': self.otk['public'][i].x.to_bytes(32, byteorder='big').hex(),
                    'Y': self.otk['public'][i].y.to_bytes(32, byteorder='big').hex()
                })
            json.dump(jsonized, f)

    # Client functions provided by the instructor

    def reset_otks(self):
        signature = self.digital_signature.sign(self.student_id, self.keys['private'])
        mes = {'ID': self.student_id, 'H': signature.h, 'S': signature.s}
        response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json = mes)		
        if((response.ok) == False): print(response.json())
        else:
            print('Successfully reset OTKs.')

    def __register_one_time_keys(self):
        for i in range(len(self.otk['privates'])):
            mes = {
                'ID': self.student_id, 
                'KEYID': i, 
                'OTKI.X': self.otk['public'][i].x, 
                'OTKI.Y': self.otk['public'][i].y,
                'HMACI': self.otk['hmac'][i]
            }
            response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
            if response.ok:
                print(f"Successfully registered one time key with id={i}.")
            else:
                print(f"Failed to register one time key with id={i}.")
                print(f"Error: {response.json()}")

    def __verify_email_code(self):
        mes = {'ID':self.student_id, 'CODE': self.code}
        response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
        if((response.ok) == False): return False, response.json()
        else:
            f = open('Identity_Key.txt', 'w')
            f.write("IK.Prv: "+str(self.keys['private'])+"\n"+"IK.Pub.x: "+str(self.keys['public'].x)+"\n"+"IK.Pub.y: "+str(self.keys['public'].y)+"\n")
            f.close()

            return True, response.json()

    def __send_identity_to_server(self, signature: Signature):
        message = {
            'ID': self.student_id, 
            'H': signature.h, 
            'S': signature.s, 
            'IKPUB.X': self.keys['public'].x, 
            'IKPUB.Y': self.keys['public'].y
        }
        response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = message)		
        if((response.ok) == False):
            return False, response.json()
        return True, response.json()
    
    def __send_presigned_signature(self, signature: Signature):
        mes = {
            'ID': self.student_id, 
            'H': signature.h, 
            'S': signature.s, 
            'SPKPUB.X': self.presigned_keys.public.x, 
            'SPKPUB.Y': self.presigned_keys.public.y
        }
        response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)		
        if((response.ok) == False): 
            return False, response.json()
        else: 
            res = response.json()
            return True, res

if __name__ == '__main__':
    # ALPER KEYS
    key_pairs = {
        'public': {
            'x': 0xa526ea93cc3020ab68d7f0335e080ce4c346c5b33b468f1ce40f45512243a052, 
            'y': 0xcf0241c214effe9b3a866827f1f12a181bd0031053122662db5b6939abc1687f
        },
        'private': 96707718587161152128678693218471196779043027882080173409020211074670724786738
    }

    #BILGAN KEYS
    # key_pairs = {
    #     'public': {
    #         'x': 0xa526ea93cc3020ab68d7f0335e080ce4c346c5b33b468f1ce40f45512243a052, 
    #         'y': 0xcf0241c214effe9b3a866827f1f12a181bd0031053122662db5b6939abc1687f
    #     },
    #     'private': 96707718587161152128678693218471196779043027882080173409020211074670724786738
    # }

    client = SignalClient(28224, key_pairs)
    client.start()
    # client.reset_otks()