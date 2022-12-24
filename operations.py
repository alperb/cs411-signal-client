import math
import time
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json
from signing import DigSig

API_URL = 'http://10.92.55.4:5000'

stuID = 27846 #Enter Your ID

#Server's Identitiy public key
IKey_Ser = 1.0 # dummy value # Use the values in the project description document to form the server's IK as a point on the EC. Note that the values should be in decimal.
IKey_Pr = 1.0 # dummy value
IKey_Pub = 1.0

IKey_Pub_x = 0x67d8b1f5c27e23e8ab9a58b7654d026ca13aa8ba8e1e92c40aa093b77577a693
IKey_Pub_y = 0xe721a2183c9b465d001d19d2e756c297176dacb9f53c559394e1aee25de1df8a

IKey_Pr = 15190466278424233643069638666740506914852358611055143956296563220498701913495


def IKRegReq(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    if((response.ok) == False): print(response.json())

def IKRegVerify(code):
    mes = {'ID':stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    else:
        print(response.json())
        f = open('Identity_Key.txt', 'w')
        f.write("IK.Prv: "+str(IKey_Pr)+"\n"+"IK.Pub.x: "+str(IKey_Pub_x)+"\n"+"IK.Pub.y: "+str(IKey_Pub_y))
        f.close()

def SPKReg(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)		
    if((response.ok) == False): 
        print(response.json())
    else: 
        res = response.json()
        return res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']

def OTKReg(keyID,x,y,hmac):
    mes = {'ID':stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True


def ResetIK(rcode):
    mes = {'ID':stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetSPK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True


def ResetOTK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json = mes)		
    if((response.ok) == False): print(response.json())


signer = DigSig()
# Registration of Identity Keys
#IKey_Pr, IKey_Pub = signer.generate_keys()
#signature = signer.sign(stuID, IKey_Pr)
#IKRegReq(signature.h, signature.s, IKey_Pub.x, IKey_Pub.y)




#Verification of Identity Keys
#IKRegVerify(774776)




# Registration of SPK
#SPK_Pr, SPK_Pub = signer.generate_keys()
#concatted = int.from_bytes(SPK_Pub.x.to_bytes(32, byteorder='big') + SPK_Pub.y.to_bytes(32, byteorder='big'), byteorder='big')
#signature_spk = signer.sign(concatted, IKey_Pr)
#SPK_S_x, SPK_S_y, h_S, s_S = SPKReg(signature_spk.h, signature_spk.s, SPK_Pub.x, SPK_Pub.y)
#print("SPK_S_x: ", SPK_S_x)
#print("SPK_S_y: ", SPK_S_y)
#print("h_S: ", h_S)
#print("s_S: ", s_S)

SPK_S_x, SPK_S_y, h_S, s_S  = (56639757923349849611343281406087185169440496922691141801327518124754702485302, 60393615797913336386435708272243523005927060424158141789698645816131859206963, 110235389983263353264354483553323649982450696252564866551091996252800229873330, 6899407087835871525818865453449912461726247877860035085524895301935089518334)

# UYARIUYARI After you check the validity ofthe signature ofSPKS.Pub, you may use it 
#bu stepi yapmadim

SPK_Pr = 28886565754216759207177581893985453110039657069970572445198802222912685475893
SPK_Pub_x = 0x1617f71cfca2099f2f7f89a89d1d892943618c80b29408274b55ffe7c4790892
SPK_Pub_y = 0x50b2c7d4f477903d66212a8e078e163be020b611297816b4286786d43a89f3c4


T_x = (SPK_Pr * SPK_S_x) 
T_y = (SPK_Pr * SPK_S_y) 

U = b'CuriosityIsTheHMACKeyToCreativity' + T_y.to_bytes((T_y.bit_length()+7)//8, byteorder='big') + T_x.to_bytes((T_x.bit_length()+7)//8, byteorder='big')
print(U)
K = SHA3_256.new(U).digest()


OTK_Pr = []
OTK_Pub = []
HMACs = []
for i in range(10):
    OTK_Pr_i, OTK_Pub_i = signer.generate_keys()
    OTK_Pr.append(OTK_Pr_i)
    OTK_Pub.append(OTK_Pub_i)
    concatted = OTK_Pub_i.x.to_bytes((OTK_Pub_i.x.bit_length()+7)//8, byteorder='big') + OTK_Pub_i.y.to_bytes((OTK_Pub_i.y.bit_length()+7)//8, byteorder='big')
    hmac_i = HMAC.new(key=K, msg=concatted, digestmod=SHA256).hexdigest()
    HMACs.append(hmac_i)
    print(OTKReg(i, OTK_Pub_i.x, OTK_Pub_i.y, hmac_i))
    break
    



