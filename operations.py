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
from signing import DigSig, Signature

API_URL = 'http://10.92.55.4:5000'

stuID = 27846 #Enter Your ID

#Server's Identitiy public key
IKey_Ser = 1.0 # dummy value # Use the values in the project description document to form the server's IK as a point on the EC. Note that the values should be in decimal.
IKey_Pr = 1.0 # dummy value
IKey_Pub = 1.0

IKey_Pub_x = 46971090604841360079922061551181542211820613641553712113849057601064265033363
IKey_Pub_y = 104543692712201736351209024090219336184678725720224627814416251244961731829642

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

def step1():
    # Registration of Identity Keys
    IKey_Pr, IKey_Pub = signer.generate_keys()
    signature = signer.sign(stuID, IKey_Pr)
    IKRegReq(signature.h, signature.s, IKey_Pub.x, IKey_Pub.y)
    print("IKey_Pr: ", IKey_Pr)
    print("IKey_Pub.x: ", IKey_Pub.x)
    print("IKey_Pub.y: ", IKey_Pub.y)

    print("STEP 1 DONE")
    step2()

def step2():
    # Verification of Identity Keys
    code = input("Enter the code sent to your email: ")
    IKRegVerify(int(code))

    print("STEP 2 DONE")

    step3()

def step3():
    # Registration of SPK
    SPK_Pr, SPK_Pub = signer.generate_keys()
    print("SPK_Pr: ", SPK_Pr)
    print("SPK_Pub.x: ", SPK_Pub.x)
    print("SPK_Pub.y: ", SPK_Pub.y)

    concatted = int.from_bytes(SPK_Pub.x.to_bytes(32, byteorder='big') + SPK_Pub.y.to_bytes(32, byteorder='big'), byteorder='big')
    signature_spk = signer.sign(concatted, IKey_Pr) 

    SPK_S_x, SPK_S_y, h_S, s_S = SPKReg(signature_spk.h, signature_spk.s, SPK_Pub.x, SPK_Pub.y)
    print("SPK_S_x: ", SPK_S_x)
    print("SPK_S_y: ", SPK_S_y)
    print("h_S: ", h_S)
    print("s_S: ", s_S)

    print("STEP 3 DONE")
    step4(SPK_S_x, SPK_S_y, h_S, s_S, SPK_Pr, SPK_Pub)


#Verify SPK from server
def step4(SPK_S_x, SPK_S_y, h_S, s_S, SPK_Pr, SPK_Pub):
    # Verification of SPK
    concatted = int.from_bytes(SPK_S_x.to_bytes((SPK_S_x.bit_length()+7)//8, byteorder='big') + SPK_S_y.to_bytes((SPK_S_y.bit_length()+7)//8, byteorder='big'), byteorder='big')
    signer.verify(concatted, Signature(h_S, s_S), Point(SPK_S_x, SPK_S_y, signer.curve, True))
    
    print("STEP 4 DONE")
  #  step5(SPK_Pr, SPK_S_x, SPK_S_y)


def step5(SPK_Pr, SPK_S_x, SPK_S_y):
    T_x = (SPK_Pr * SPK_S_x) 
    T_y = (SPK_Pr * SPK_S_y) 
    print("T_x: ", T_x)
    print("T_y: ", T_y)


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



SPK_S_x = 56639757923349849611343281406087185169440496922691141801327518124754702485302
SPK_S_y = 60393615797913336386435708272243523005927060424158141789698645816131859206963
h_S = 21621129333516383416415033250076862473303546494646545610293211657087856064840
s_S = 73638652723800134909762146909643356402590833432990662757215424834350273257058

SPK_Pr = 96781178905338882692128991514392085794127164657343499832134463045561619700020
SPK_Pub = Point(20657832657563502899009328608755815246024178484769830595404327207056088688056, 41818993896524601909631861043247216085464697660955570721667917106157500659378, signer.curve, True)

#step3()
step4(SPK_S_x, SPK_S_y, h_S, s_S, SPK_Pr, SPK_Pub)

#sign STUID
#signature = signer.sign(stuID, IKey_Pr)
#ResetSPK(signature.h, signature.s)

