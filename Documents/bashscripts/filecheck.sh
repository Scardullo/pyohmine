#!/bin/bash

if [[ -s drive.txt ]]
# -s = exists & not empty | -a & -e both same = exists  | -f = file | -d = directory
then
	echo "That was true"
else
	echo "That was false"
fi

# man test