#!/bin/bash

x=1
while [[ $x -le 10 ]]
do 
 echo $x
 ((x++))   # integer no $
done

y=10
until [[ $y -le 1 ]]
do 
 echo $y
 ((y--))
done

for z in 1 2 3 4 
do
 echo $z
done

for a in {1..10}
do 
 echo $a
done

