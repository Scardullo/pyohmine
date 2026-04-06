#!/bin/bash

myvar=1

while [ $myvar -le 10 ]
do 
    echo $myvar
    myvar=$(( $myvar +1 ))
    sleep 0.5
done

myvar=1

while [ -f testfile ]
do
    echo "The test file exists"
done

echo "The file no longer exists, exiting"
