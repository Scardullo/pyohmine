#!/bin/bash

echo "Enter A B C or D?"

read text

case $text in
	A)
		echo "Result A"
		echo "Result A 2";;
	B)
		echo "Result B";;
	C)
		echo "Result C";;
	D)
		echo "result D";;
	*)
		echo "Try Again";;
esac

# from here on down is not part of the case example

echo "What is your first name?"
read first
echo "What is your last name?"
read last

if [[ ($first == "Anthony" || $first == "Tony") && $last == "Scardullo" ]]
then
	echo "Welcome Linux Administrator"
fi
