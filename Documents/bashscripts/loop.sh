#!/bin/bash

for a in {1..10..2}
do 
 echo $a
done

for n in $(cat ./names.txt)
do 
 echo $n
done

while true
do 
 echo "who are you?"
 read name
 if [[ $name == "earl" ]]
 then
  break
 fi
 echo "Hi $name!"
done
echo "$name ruins everything"

for c in {1..20}
do 
 if [[ $c == 13 ]]
 then
  continue
 fi
 echo "Elevator stopping on floor $c"
 sleep 0.25
done




