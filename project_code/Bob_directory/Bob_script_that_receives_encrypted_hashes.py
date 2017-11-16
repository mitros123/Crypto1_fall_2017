#!/usr/bin/env python3

import os
import sys
from subprocess import Popen, PIPE
from Crypto import Random
from Crypto.Random import random
from Crypto.PublicKey import ElGamal
from Crypto.Util.number import GCD
from Crypto.Cipher import AES
from Crypto.Hash import HMAC,SHA256
import time
import base64


def find_hashes_names_indexes_of_our_files():
    global hashes
    global names
    global indexes

    process=Popen(["../find_hash_for_every_file.sh", we_are+'_files/'], stdout=PIPE,stderr=PIPE)
    stdout, stderr = process.communicate()
    stdout_str=stdout.decode('ascii').split('\n')
    stdout_str = list(filter(None, stdout_str)) #Remove empty strings from list
    for line in stdout_str:
        hashes.append(line.split('-')[0].strip())
        names.append(line.split('-')[1].strip())
        indexes.append(line.split('-')[2].strip())


def unsafe_send(msg):
    global wp
    #puts msg in the "network", encoded
    wp.write(turn_byte_string_into_normal_str(base64.b64encode(msg))+"\n")
    wp.flush()
    #close_and_reopen_write_pipe() #make sure the message is sent

def unsafe_recv():
    global rp
    #receives msg from the "network", encoded
    msg=rp.readline()
    msg=msg[:-1]
    return base64.b64decode(turn_str_into_byte_string_of_same_value(msg))

def add_nonce_to_msg(msg):
    #msg is a normal string
    global nonce
    nonce+=1
    return(str(nonce)+"--->"+msg)

def verify_nonce_of_msg(msg):
    #msg is a normal string
    global nonce
    nonce_recv=int(msg.split("--->")[0])
    if (nonce_recv!=nonce+1):
        sys.stderr.write("Error in nonce! wanted "+str(nonce+1)+" and got "+str(nonce_recv)+"\n")
        exit(-1)
    nonce+=1
    return (msg.split("--->")[1])

   
def verify_hmac_of_msg_and_return_proper_msg(msg,mac_key):
    #msg is a byte string, mac_key is an integer. Returns a byte string
    proper_msg=msg.split(b"|")[0]
    hmac_of_msg=msg.split(b"|")[1]
    if (hmac(proper_msg,mac_key)!=turn_byte_string_into_normal_str(hmac_of_msg)):
        sys.stderr.write("Error in hmac! wanted "+hmac(proper_msg,mac_key)+" and got "+turn_byte_string_into_normal_str(hmac_of_msg)+"\n")
        exit(-1)
    return proper_msg 

def close_and_reopen_write_pipe():
    #forces flush of data
    global wp
    wp.close()
    time.sleep(0.25)
    wp=open(out_pipe,'w')

def close_and_reopen_read_pipe():
    global rp
    rp.close()
    time.sleep(0.25)
    rp=open(in_pipe,'r')

def turn_decimal_int_into_byte_string_of_same_value(dec_int):
    hex_repr=hex(dec_int).split("x")[1]
    if (len(hex_repr)%2==1):
        hex_repr="0"+hex_repr
    ret_str=bytes(bytearray.fromhex(hex_repr))
    return ret_str

def turn_str_into_byte_string_of_same_value(str_in):
    return str_in.encode("utf-8")

def turn_byte_string_into_normal_str(bytestr):
    return bytestr.decode("utf-8")

#https://www.dlitz.net/software/pycrypto/api/current/Crypto.Hash.HMAC-module.html
def hmac(msg,mac_key):
    #returns mac of a message as a *normal* string. msg is a byte str, mac_key is an int
    secret_for_hmac=turn_decimal_int_into_byte_string_of_same_value(mac_key)
    h = HMAC.new(secret_for_hmac,digestmod=SHA256)
    h.update(msg)
    return h.hexdigest()

#https://stackoverflow.com/questions/14179784/python-encrypting-with-pycrypto-aes
def pad_data(data):
    #data is a byte string
    length = AES.block_size - (len(data) % AES.block_size)
    ret_data =data+ bytes([length])*length
    return ret_data

def unpad_data(data):
    #data is a byte string
    ret_data= data[:-data[-1]]
    return ret_data

#https://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
def encrypt_aes_cbc(str_to_encrypt,aes_key):
    #str_to_encrypt is a normal string. aes_key is an integer
    byte_str_to_encrypt=turn_str_into_byte_string_of_same_value(str_to_encrypt)
    byte_str_to_encrypt=pad_data(byte_str_to_encrypt)
    iv = Random.new().read( AES.block_size )
    aes_key_as_byte_str=turn_decimal_int_into_byte_string_of_same_value(aes_key)
    #now byte_str_to_encrypt, iv, aes_key_as_byte_str are all byte strings
    cipher = AES.new( aes_key_as_byte_str, AES.MODE_CBC, iv )
    return base64.b64encode( iv + cipher.encrypt( byte_str_to_encrypt ) ) 
    
def decrypt_aes_cbc(str_to_decrypt,aes_key):
    #str_to_encrypt is a byte string. aes_key is an integer. Returns a byte string
    enc = base64.b64decode(str_to_decrypt)
    iv = enc[:AES.block_size]
    aes_key_as_byte_str=turn_decimal_int_into_byte_string_of_same_value(aes_key)
    cipher = AES.new(aes_key_as_byte_str, AES.MODE_CBC, iv )
    return unpad_data(cipher.decrypt( enc[AES.block_size:] ))


def secure_symmetric_send(msg,aes_key,mac_key):
    #msg is a normal string, and the keys are integers
    new_msg=add_nonce_to_msg(msg) #new_msg is a normal string
    new_msg=encrypt_aes_cbc(new_msg,aes_key) #new_msg is a byte string now (the output of base64), and remains as such
    new_msg=new_msg+b'|'+turn_str_into_byte_string_of_same_value(hmac(new_msg,mac_key)) #encrypt-then-mac
    unsafe_send(new_msg)

def secure_symmetric_recv(aes_key,mac_key):
    #the keys are integers
    msg=unsafe_recv() #msg is a byte string
    msg=verify_hmac_of_msg_and_return_proper_msg(msg,mac_key) #msg is still a byte string
    msg=decrypt_aes_cbc(msg,aes_key) #msg is still a byte string
    msg=turn_byte_string_into_normal_str(msg) #now msg becomes a normal string
    msg=verify_nonce_of_msg(msg)
    return msg


we_are='Bob'
they_are='Alice'
num_of_total_files=100
nonce=0;

in_pipe='../'+they_are+'_out_'+we_are+'_in'
out_pipe='../'+we_are+'_out_'+they_are+'_in'

#open pipes
wp=open(out_pipe,'w')
rp=open(in_pipe, 'r')


#get the hashes of our files
hashes=[] #the hashes in hex
indexes=[]  #the indexes of the files in the directory
names=[]    #the names of the files
print("Finding hashes, names and indexes of our files...")
find_hashes_names_indexes_of_our_files()
print("Found them.")



print("Fetching "+they_are+"'s public key info. We assume this part is not tampered with.")
pubkey_info=turn_byte_string_into_normal_str(unsafe_recv()+unsafe_recv()+unsafe_recv())
pubkey_list=pubkey_info.split("\n")
pubkey_list= list(filter(None, pubkey_list)) #Remove empty strings from list of strings
pubkey_of_other={}
pubkey_of_other["p"]=int(pubkey_list[0]) #prime
pubkey_of_other["g"]=int(pubkey_list[1]) #generator
pubkey_of_other["y"]=int(pubkey_list[2]) #public key
print("Got public key info.")


print("Generating symmetric key and authentication key for symmetric encryption...")
aes_key=random.StrongRandom().randint(1,2**128-1)
mac_key=random.StrongRandom().randint(1,2**128-1)
aes_key_mac_enc=ElGamal.ElGamalobj()
aes_key_mac_enc.p=pubkey_of_other["p"]; aes_key_mac_enc.g=pubkey_of_other["g"]; aes_key_mac_enc.y=pubkey_of_other["y"]; #set the El Gamal values
#https://www.dlitz.net/software/pycrypto/api/current/Crypto.PublicKey.ElGamal.ElGamalobj-class.html#encrypt
#put them both in the same message
aes_key_mac_enc_num=aes_key_mac_enc.encrypt(turn_str_into_byte_string_of_same_value(str(aes_key)+"|"+str(mac_key)),random.StrongRandom().randint(1,pubkey_of_other["p"]-2))

print(aes_key)
print(mac_key)

aes_key_mac_enc_num_b64_1=base64.b64encode(aes_key_mac_enc_num[0]).decode('utf-8') #encode in base64 before sending
aes_key_mac_enc_num_b64_2=base64.b64encode(aes_key_mac_enc_num[1]).decode('utf-8') 
print("Sending AES key and MAC key to the other party...")
unsafe_send(turn_str_into_byte_string_of_same_value(aes_key_mac_enc_num_b64_1+"\n"))
unsafe_send(turn_str_into_byte_string_of_same_value(aes_key_mac_enc_num_b64_2+"\n"))
#close_and_reopen_write_pipe() #make sure they arrive
print("Sent AES key and MAC key to the other party.")

print("From now on, all encryption will be done using symmetric crypto + nonces to protect from replay attacks.")



print("Receiving hashes...")
responses=[]
for i in range(num_of_total_files):
    responses.append(secure_symmetric_recv(aes_key,mac_key).replace("\n",""))#receive the hashes but remove the newline
print(responses)
responses= list(filter(None, responses)) #Remove empty strings from list of strings


#find the common hashes and print the names
for resp in responses:
    for i,hash_of_our_files in enumerate(hashes):
        if (resp==hash_of_our_files):
            print(names[i])


#close pipes
time.sleep(2)
rp.close()
wp.close()
