#!/usr/bin/env python3

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


def close_and_reopen_write_pipe():
    #forces flush of data
    global wp
    wp.close()
    wp=open(out_pipe,'w')

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
pubkey_info=rp.read()
pubkey_list=pubkey_info.split("\n")
pubkey_list= list(filter(None, pubkey_list)) #Remove empty strings from list of strings
pubkey_of_other={}
pubkey_of_other["p"]=int(pubkey_list[0]) #prime
pubkey_of_other["g"]=int(pubkey_list[1]) #generator
pubkey_of_other["y"]=int(pubkey_list[2]) #public key
print("Got public key info.")


print("Generating symmetric key and IV for symmetric encryption...")
aes_key=random.StrongRandom().randint(1,2**128-1)
aes_iv=random.StrongRandom().randint(1,2**128-1)
aes_key_iv_enc=ElGamal.ElGamalobj()
aes_key_iv_enc.p=pubkey_of_other["p"]; aes_key_iv_enc.g=pubkey_of_other["g"]; aes_key_iv_enc.y=pubkey_of_other["y"]; 
aes_key_iv_enc_num=aes_key_iv_enc.encrypt((str(aes_key)+"|"+str(aes_iv)).encode('utf-8'),random.StrongRandom().randint(1,pubkey_of_other["p"]-2))

print(aes_key)
print(aes_iv)

aes_key_iv_enc_num_b64_1=base64.b64encode(aes_key_iv_enc_num[0]).decode('utf-8')
aes_key_iv_enc_num_b64_2=base64.b64encode(aes_key_iv_enc_num[1]).decode('utf-8')
print("Sending AES key and IV to the other party...")
wp.write(aes_key_iv_enc_num_b64_1+"\n")
wp.write(aes_key_iv_enc_num_b64_2+"\n")
close_and_reopen_write_pipe()
#wp.write(aes_iv_enc_num[0]+"\n")



'''
responses=[]
responses_in_one_line=rp.read() #receive the hashes
responses=responses_in_one_line.split('\n')
responses= list(filter(None, responses)) #Remove empty strings from list of strings


#find the common hashes and print the names
for resp in responses:
    for i,hash_of_our_files in enumerate(hashes):
        if (resp==hash_of_our_files):
            print(names[i])
'''

#close pipes
rp.close()
wp.close()
