#!/bin/bash

declare -A y
y[abc]=123
y[efg]="xxx"
declare -A z
z=( [abc]=123 [efg]="xxx" )
echo ${y[abc]}
echo ${z[efg]}
