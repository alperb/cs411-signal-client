import os
import random
import time
import math
import requests
import json
import sys

from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
from Crypto.Cipher import AES
from Crypto import Random

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

class OTK(object):
    def __init__(self, id, x, y):
        self.id = id
        self.x = x
        self.y = y
    
    def get_point(self):
        return Point(self.x, self.y, Curve.get_curve('secp256k1'))

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
            return True
        else:
            return False

    def __to_bytes(self, n):
        return n.to_bytes((n.bit_length()+7)//8, byteorder='big')

class SessionContext(object):
    def __init__(self, student_id: int, to: int, ephemeral_key: Keys, receiver_otk: OTK, session_key: bytes):
        self.student_id = student_id
        self.to = to
        self.ephemeral_key = ephemeral_key
        self.receiver_otk = receiver_otk
        self.session_key = session_key

        self.message_id = 1
    
    def send_message(self, message: str):
        kdf_enc, kdf_mac, kdf_next = self.__generate_kdf(self.session_key)

        nonce = os.urandom(8)
        cipher = AES.new(kdf_enc, AES.MODE_CTR, nonce=nonce)
        ciphertext = cipher.encrypt(message.encode())
        hmac = HMAC.new(kdf_mac, ciphertext, digestmod=SHA256).digest()

        concatted = int.from_bytes(
            nonce +
            ciphertext +
            hmac
        , byteorder='big')

        self.__send_message_request(concatted)

    def __generate_kdf(self, key: bytes):
        t = key + b'YouTalkingToMe'
        k_enc = SHA3_256.new(t).digest()

        t_mac = key + k_enc + b'YouCannotHandleTheTruth'
        k_mac = SHA3_256.new(t_mac).digest()

        t_next = k_enc + k_mac + b'MayTheForceBeWithYou'
        k_next = SHA3_256.new(t_next).digest()

        return k_enc, k_mac, k_next
    
    def __send_message_request(self, concatted: int):
        mes = {
            "IDA": self.student_id, 
            "IDB": self.to, 
            "OTKID": int(self.receiver_otk.id), 
            "MSGID": int(self.message_id), 
            "MSG": concatted, 
            "EK.X": self.ephemeral_key.public.x, 
            "EK.Y": self.ephemeral_key.public.y
        }
        response = requests.put('{}/{}'.format(API_URL, "SendMSG"), json=mes)
        print(response.json()) 

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
    
    def register(self):
        self.register_identity()
        self.verify_server_code()
        self.register_presigned_keys()
        self.verify_spk_from_server()
        self.generate_otk()

    def start(self):
        self.read_otks()
     

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
            exit(1)

    def verify_server_code(self):
        self.code = int(input("\nEnter the code sent to your email: "))
        res = self.__verify_email_code()

        if res:
            print("Successfully verified email code.")
            print(f"Server response: {res[1]}")
        else:
            print("Failed to verify email code.")
            print(f"Error: {res[1]}")
            exit(1)
    
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
            exit(1)

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
            exit(1)
    
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
    
    def generate_session_key(self, otk_idx: int, ephemeral_key: Point):
        t = self.otk['privates'][otk_idx] * ephemeral_key
        u = self.__to_bytes(t.x) + self.__to_bytes(t.y) + b'ToBeOrNotToBe'
        return SHA3_256.new(u).digest()
    
    def generate_session_key_from(self, otk: OTK, ephemeral_key: Keys):
        t = otk.get_point() * ephemeral_key.private
        u = self.__to_bytes(t.x) + self.__to_bytes(t.y) + b'ToBeOrNotToBe'
        return SHA3_256.new(u).digest()
    
    def generate_ephemeral_key(self):
        return self.digital_signature.generate_keys()

    def generate_kdf(self, key: bytes):
        t = key + b'YouTalkingToMe'
        k_enc = SHA3_256.new(t).digest()

        t_mac = key + k_enc + b'YouCannotHandleTheTruth'
        k_mac = SHA3_256.new(t_mac).digest()

        t_next = k_enc + k_mac + b'MayTheForceBeWithYou'
        k_next = SHA3_256.new(t_next).digest()

        return k_enc, k_mac, k_next
    
    def decrypt_message(self, message: bytes, key: bytes, nonce):
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        plaintext = cipher.decrypt(message)
        return plaintext

    def fetch_message(self):
        k_next = None
        messages = []

        print('-------FETCHING MESSAGES-------\n')

        while True:

            m = self.__request_message()
            if not m:
                break
            mid = m['message_id']
            print(f'\n -------RECEIVED MESSAGE { mid }-------\n')

            if k_next is None:
                session_key = self.generate_session_key( m['otk'], Point(m['ek']['x'], m['ek']['y'], self.digital_signature.curve) )
                kdf_enc, kdf_mac, kdf_next = self.generate_kdf(session_key)
            else:
                kdf_enc, kdf_mac, kdf_next = self.generate_kdf(k_next)

            k_next = kdf_next
            nnn = m['message'].to_bytes((m['message'].bit_length()+7)//8, byteorder='big')
            nonce = nnn[:8]
            message = nnn[8:-32]
            mac = nnn[-32:]

            decrypted = self.decrypt_message(message, kdf_enc, nonce)
            decrypted = decrypted.decode('utf-8')

            # Calculate MAC with SHA2 256
            h = HMAC.new(kdf_mac, message, digestmod=SHA256).digest()
            if mac == h:
                #self.__send_decrypted_message(int(m['message_id']), decrypted, int(m['sender']))
                messages.append({"id": int(m['message_id']), "message": decrypted, "sender": int(m['sender'])})

        deleted = self.__get_deleted_message()

        for message in messages:
            mid = message['id']
            sender = message['sender']
            m = message['message']
            if mid not in deleted:
                print(f'Message { mid } - {m} - Read')
            else:
                print(f'Message { mid } - Was deleted by sender - X')
        
        return messages
    
    def create_session(self, to: int):
        ephemeral = self.generate_ephemeral_key()
        otk_of_receiver = self.__request_otk_of(to)
        if not otk_of_receiver:
            return None
        session_key = self.generate_session_key_from(otk_of_receiver, ephemeral)

        return SessionContext(self.student_id, to, ephemeral, otk_of_receiver, session_key)

    def send_message(self, ctx: SessionContext, message: str):
        ctx.send_message(message)
        return ctx
    
    def check_status(self):
        return self.__check_status()
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
        
    def read_otks(self):
        with open('otk.json', 'r') as f:
            self.otk = json.load(f)
            for i in range(len(self.otk['privates'])):
                self.otk['privates'][i] = int.from_bytes(bytes.fromhex(self.otk['privates'][i]), byteorder='big')
            for i in range(len(self.otk['public'])):
                self.otk['public'][i] = Point(
                    int.from_bytes(bytes.fromhex(self.otk['public'][i]['X']), byteorder='big'),
                    int.from_bytes(bytes.fromhex(self.otk['public'][i]['Y']), byteorder='big'),
                    self.digital_signature.curve
                )
        print(self.otk)

    # Client functions provided by the instructor

    def __check_status(self):
        signature = self.digital_signature.sign(self.student_id, self.keys['private'])
        mes = {'ID': self.student_id, 'H': signature.h, 'S': signature.s}
        response = requests.get('{}/{}'.format(API_URL, "Status"), json = mes)
        if (response.ok == True):
            res = response.json()
            return res['numMSG'], res['numOTK'], res['StatusMSG']
        else:
            return False

    def __request_otk_of(self, sid):
        signature = self.digital_signature.sign(sid, self.keys['private'])
        mes = {'IDA': self.student_id, 'IDB': sid, 'H': signature.h, 'S': signature.s}
        response = requests.get('{}/{}'.format(API_URL, "ReqOTK"), json = mes)
        if (response.ok) == True:
            res = response.json()
            return OTK(res['KEYID'], res['OTK.X'], res['OTK.Y'])
        else:
            print(response.json())
            return False

    def __get_deleted_message(self):
        signature = self.digital_signature.sign(self.student_id, self.keys['private'])
        mes = {'ID': self.student_id, 'H': signature.h, 'S': signature.s}
        response = requests.get('{}/{}'.format(API_URL, "ReqDelMsgs"), json = mes)	
        if (response.ok) == True:
            return response.json()['MSGID']

    def __send_decrypted_message(self, mid: int, message: str, sender: int):
        mes = {'IDA': self.student_id, 'IDB': sender, 'MSGID': mid, 'DECMSG': message}
        response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)		
        print(response.json())

    def __request_message(self):
        signature = self.digital_signature.sign(self.student_id, self.keys['private'])
        mes = {'ID': self.student_id, 'H': signature.h, 'S': signature.s}
        response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)	
        if (response.ok) == True: 
            res = response.json()
            print(res)
            return {
                "sender": res["IDB"],
                "message": res["MSG"],
                "message_id": res["MSGID"],
                "ek": {
                    "x": res["EK.X"],
                    "y": res["EK.Y"]
                },
                "otk": res['OTKID']
            }
        else:
            return None

    def send_psuedo_message(self):
        signature = self.digital_signature.sign(self.student_id, self.keys['private'])
        mes = {'ID': self.student_id, 'H': signature.h, 'S': signature.s}
        response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json = mes)		
        print(response.json())

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

    # Public and private keys
    key_pairs = {
        'public': {
            'x': 89897491541447362280560858232937117506845597473304053345085453511818452134240, 
            'y': 104889529118147695129117292097117733292273420935000879173869799576866952013590
        },
        'private': 95336075571880778169962111676182110626057541902580027651120072588122040526823
    }

    if len(sys.argv) < 2:
        print("Usage: python3 client.py <student_id>")
        exit(1)

    student_id = int(sys.argv[1])

    # Reset keys if requested with --generate flag
    if len(sys.argv) > 2 and sys.argv[2] == '--generate':
        rcode = int(input('Please enter your recovery code: '))
        mes = { 'ID': student_id, 'RCODE': rcode }
        print('Resetting current keys...')
        response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
        if((response.ok) == False):
            print('Failed to reset keys.')
            print(response.json())
            exit(1)
        else:
            print('Keys reset successfully.')

        # Generate new keys
        print(f'Generating new keys for student {student_id}...')
        digsig = DigitalSignature()
        generated = digsig.generate_keys()
        key_pairs = {
            'public': {
                'x': generated.public.x,
                'y': generated.public.y
            },
            'private': generated.private
        }
        print(f'Keys generated successfully.')

        print('Writing keys to file...')
        f = open('keys.txt', 'w')
        s = f"""X: {key_pairs['public']['x']}
Y: {key_pairs['public']['y']}
P: {key_pairs['private']}
"""
        f.write(s)
        f.close()
        print('Keys written to `keys.txt` successfully.')
        exit(0)

    client = SignalClient(student_id, key_pairs)
    
    # registers the ik and spk with the server
    # registers presigned keys with the server
    # only necessary if the keys are not registered
    client.register()

    # starts the client
    # verifies servers spk
    # reads otk's from local file
    client.start()


    ## make psuedo-client send you 5 messages
    # client.send_psuedo_message()

    ## fetch messages from server (max 10)
    # messages = client.fetch_message()

    ## create a session with the receiver client
    # ctx = client.create_session(26045)
    # # Sending a message to the user.
    # ctx.send_message('Hello from alper3!')
    # ctx.send_message('Hello from alper4!')

    # if not ctx:
    #     print(f'Failed to create session with client.')
    #     exit(1)

    
    ## sending back all the valid messages back to psuedo-client
    # for m in messages:
    #     print(m)
        #ctx.send_message(m['message'])
    

    ## reset otks
    # client.reset_otks()

    ## check otk status
    # msgs, otks, text = client.check_status()
    # print(text)
    # print(f'You have {otks} OTKs left.')
    # print(f'You have {msgs} messages in your inbox.')
    # if otks == 0:
    #     print('You have no OTKs left. Registering new OTKs...')
    #     client.generate_otk()