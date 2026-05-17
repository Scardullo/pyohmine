#!/bin/bash

cava | while read -r line; do
    out=""

    for v in ${line//;/ }; do
        case $v in
            0) out+="▁";;
            1) out+="▁";;
            2) out+="▂";;
            3) out+="▃";;
            4) out+="▄";;
            5) out+="▅";;
            6) out+="▆";;
            7) out+="█";;
        esac
    done

    echo "$out"
done
