#!/bin/bash
IFS=$'\n'
if [ ! -d 400x400 ];  then   # create subdirectory
  mkdir 400x400
fi
for filename in $*;  do  # process all JPEG files 
  echo "processing $filename"
  magick -size 400x400 -resize 400x400 "$filename" \
  "400x400/$filname"
done

