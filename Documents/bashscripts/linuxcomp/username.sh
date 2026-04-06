#!/bin/bash

while read username; do
  pw="username-1234"
  echo "Account: $username  Password: $pw"
  useradd $username
  echo "$username:$pw" | chpasswd
  chage -d 0 -E 2024-12-31 $username
done < lastnames.txt


