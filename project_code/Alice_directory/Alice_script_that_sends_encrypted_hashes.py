#!/usr/bin/env python3

#uses Elgamal from https://www.dlitz.net/software/pycrypto/api/current/Crypto.PublicKey.ElGamal-module.html

import os
import sys
from subprocess import Popen, PIPE
from Crypto import Random
from Crypto.Random import random
from Crypto.PublicKey import ElGamal
from Crypto.Util.number import GCD
from Crypto.Cipher import AES
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
    wp.write(base64.b64encode(msg))

def unsafe_recv():
    msg=rp.read()
    return base64.b64decode(msg)

def send_with_nonce(msg):
    #no encryption
    global nonce
    nonce+=1
    unsafe_send(str(nonce)+"--->"+msg)

def recv_with_nonce():
    #no encryption
    global nonce
    msg=unsafe_recv()
    nonce_recv=int(msg.split("--->")[0])
    if (nonce_recv!=nonce+1):
        sys.stderr.write("Error in nonce! wanted "+str(nonce+1)+" and got "+str(nonce_recv)+"\n")
        exit(-1)
    return (msg.split("--->")[1])
    
def close_and_reopen_write_pipe():
    #forces flush of data
    global wp
    wp.close()
    wp=open(out_pipe,'w')


we_are='Alice'
they_are='Bob'
num_of_total_files=100
nonce=0

in_pipe='../'+they_are+'_out_'+we_are+'_in'
out_pipe='../'+we_are+'_out_'+they_are+'_in'

#open pipes
rp=open(in_pipe, 'r')
wp=open(out_pipe,'w')


#get the hashes of our files
hashes=[] #the hashes in hex
indexes=[] #the indexes of the files in the directory
names=[]  #the names of the files
print("Finding hashes, names and indexes of our files...")
find_hashes_names_indexes_of_our_files()
print("Found them.")






#construct Elgamal public key for communication
print("Generating public key for communication...")
pubkey = ElGamal.generate(1024, Random.new().read) #SOS! make it 2048 in the end
print("ElGamal key generated.")
#print(pubkey.p) #prime
#print(pubkey.g) #generator
#print(pubkey.y) #public key
#print(pubkey.x) #private key


print("Sending the public key and g,p. We assume this part is not tampered with.")
wp.write(str(pubkey.p)+"\n")
wp.write(str(pubkey.g)+"\n")
wp.write(str(pubkey.y)+"\n")
close_and_reopen_write_pipe()
time.sleep(0.5)
print("Sent the public key and the other parameters.")


print("Receiving AES key and IV...")
aes_key_iv=rp.read()
aes_key_iv_list=aes_key_iv.split("\n")
aes_key_iv_list= list(filter(None, aes_key_iv_list)) #Remove empty strings from list of strings
aes_key_iv_encrypted_1=base64.b64decode(aes_key_iv_list[0])
aes_key_iv_encrypted_2=base64.b64decode(aes_key_iv_list[1])
aes_key_iv_decrypted=pubkey.decrypt((aes_key_iv_encrypted_1,aes_key_iv_encrypted_2)).decode('utf-8')
aes_key=aes_key_iv_decrypted.split("|")[0].strip()
aes_iv=aes_key_iv_decrypted.split("|")[1].strip()



print(aes_key)
print(aes_iv)
print("Received AES key and IV.")


#write the hashes
#for hash_of_file in hashes:
#    wp.write(hash_of_file+"\n")


#close pipes
wp.close()
rp.close()
