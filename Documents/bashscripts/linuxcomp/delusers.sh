#!/bin/bash
while read username; do 
  userdel  -r $username
done < lastnames.txt

