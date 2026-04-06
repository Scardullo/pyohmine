#!/bin/bash

echo "
My command is '$0'
There are $# arguments
  The first is  '$1'
  The second is '$2'
  The third is  '$3'
  The fourth is '$4'
"
echo "Shifting...."
shift 3
echo "
There are now only $# arguments
  First is  '$1'
  Second is '$2'
  Third is  '$3'
  Fourth is '$4'
"


