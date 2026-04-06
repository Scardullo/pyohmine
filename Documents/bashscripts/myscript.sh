#!/bin/bash

lines=$(ls -lh $1 | wc -l)
logfile=job_results.log

/usr/bin/echo "The script ran at the following time: $(/usr/bin/date)" > $logfile
if [ $# -ne 1 ]
then
    echo "This script requires exactly one directory path"
    echo "Plese try again"
    exit
fi

echo "You have $(($lines-1)) objects in the $1 driectory."
