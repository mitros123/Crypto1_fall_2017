#!/bin/bash

#calculates the hashes of the files in the directory given as the first argument
#outputs a list of the hashes, sorted, with the name of the files appended

ROOT_DIR=`pwd`
DIR_WITH_FILES=${1}
HASH_CMD="sha256sum"

cd $DIR_WITH_FILES

#get the hash of every file
for file in `ls`; do
    HASH=`cat $file | $HASH_CMD`
    echo "$HASH  $file"
done |
sort #pipe the entire output of the loop to "sort" command



