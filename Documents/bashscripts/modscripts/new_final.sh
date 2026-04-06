#!/bin/bash
clear
sleep 1
echo
echo "Enter Text or STDIN"
sleep 1
echo .

if [ -t 0 ]
then
	echo "No STDIN Detected."
	echo "Enter Text"
	sleep 0.5
	echo "Bash Scripting 2.7.0 in $(date)"
    echo " Shell version $SHELL"
	sleep 0.5
	echo "Press Enter on Blank line to End"
	echo
	while true
	do
		read TEXT
		if [[ $TEXT = "" ]]; then break; fi
		RESULT+="$TEXT"$'\n'
	done
	echo "Program Terminating"
	sleep 2
else
	echo "STDIN Detected"
	sleep 0.5
	echo .
	sleep 1
	echo "Parcing Text ..."
	sleep 0.25
	echo "Still parcing"
	sleep 2
	read -d '' RESULT
fi
echo
echo
echo "Text Recall..."
echo "Processing"
echo .
sleep 1
echo "Text By ... $USER:"
echo
sleep 0.5
echo "$RESULT"
sleep 2
echo
echo "Program terminated"
echo
