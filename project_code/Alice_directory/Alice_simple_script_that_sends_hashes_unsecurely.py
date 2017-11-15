#!/usr/bin/env python3

import os
import sys
from subprocess import Popen, PIPE

we_are='Alice'
they_are='Bob'
num_of_total_files=100

in_pipe='../'+they_are+'_out_'+we_are+'_in'
out_pipe='../'+we_are+'_out_'+they_are+'_in'


#get the hashes of our files
hashes=[] #the hashes in hex
indexes=[] #the indexes of the files in the directory
names=[]  #the names of the files
process=Popen(["../find_hash_for_every_file.sh", we_are+'_files/'], stdout=PIPE,stderr=PIPE)
stdout, stderr = process.communicate()
stdout_str=stdout.decode('ascii').split('\n')
stdout_str = list(filter(None, stdout_str)) #Remove empty strings from list
for line in stdout_str:
    hashes.append(line.split('-')[0].strip())
    names.append(line.split('-')[1].strip())
    indexes.append(line.split('-')[2].strip())


#open pipes
#rp=open(in_pipe, 'r')
wp=open(out_pipe,'w')

#write the hashes
for hash_of_file in hashes:
    wp.write(hash_of_file+"\n")


#close pipes
wp.close()
#rp.close()
