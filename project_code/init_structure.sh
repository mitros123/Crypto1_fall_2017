#!/bin/bash

#initializes the structure of the crypto1 project.
#Creates directories for Alice and Bob, and puts their files in there
#It also creates 2 named pipes for the communication


ROOT_DIR="`pwd`"
ALICE_DIR="Alice_directory"
ALICE_FILES_DIR="Alice_files"
BOB_DIR="Bob_directory"
BOB_FILES_DIR="Bob_files"
NUM_OF_COMMON_FILES=20
NUM_OF_ALL_FILES=100
NUM_OF_DISTINCT_FILES=`expr $NUM_OF_ALL_FILES - $NUM_OF_COMMON_FILES`

#create Alice's directories
mkdir -p $ALICE_DIR
cd $ALICE_DIR
mkdir -p $ALICE_FILES_DIR
cd $ROOT_DIR

#create Bob's directories
mkdir -p $BOB_DIR
cd $BOB_DIR
mkdir -p $BOB_FILES_DIR
cd $ROOT_DIR

echo "Creating ${NUM_OF_COMMON_FILES} common files"
#create the common files
for ((i=1;i<=$NUM_OF_COMMON_FILES;i++)); do
    #fill common file with random data
    head -c 10M </dev/urandom > common_file_${i}
    #and move it to both directories    
    cp common_file_${i} ${ALICE_DIR}/${ALICE_FILES_DIR}/
    mv common_file_${i} ${BOB_DIR}/${BOB_FILES_DIR}/
done

#create the distinct files

#Alice's files first
echo "Creating ${NUM_OF_DISTINCT_FILES} distinct files for Alice"
cd ${ALICE_DIR}/${ALICE_FILES_DIR}/
for ((i=1;i<=$NUM_OF_DISTINCT_FILES;i++)); do
    #fill file with random data
    head -c 10M </dev/urandom > Alice_distinct_file_${i}
done
cd $ROOT_DIR

#Bob's files now
echo "Creating ${NUM_OF_DISTINCT_FILES} distinct files for Bob"
cd ${BOB_DIR}/${BOB_FILES_DIR}/
for ((i=1;i<=$NUM_OF_DISTINCT_FILES;i++)); do
    #fill file with random data
    head -c 10M </dev/urandom > Bob_distinct_file_${i}
done
cd $ROOT_DIR



 

#create the named piped for communitcation (might want to use sockets in the future, but names pipes are easier)
mkfifo Alice_out_Bob_in 2>/dev/null
mkfifo Bob_out_Alice_in 2>/dev/null

echo "Done."
