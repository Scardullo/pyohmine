#!/bin/bash

up="before"
since="function"
echo $up
echo $since


showuptime(){
       local up=$(uptime -p | cut -c4-)   # <-- local makes it not
       local since=$(uptime -s)           # <-- global / if not local then
       cat << EOF                         #     they change after function
-------
This machine has been up for ${up}
This machine has been running since ${since}
-------
EOF
}
showuptime
echo $up
echo $since


date=$(date)
disk=$(df -h)
memory=$(free -h)


echo Todays date is ${date}
echo
echo Available Memory:
echo ${memory}
echo
echo Available Disk Space:
echo
echo ${disk}
