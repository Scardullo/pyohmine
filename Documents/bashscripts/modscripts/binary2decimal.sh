#!/bin/bash
# binary_to_decimal.sh
# Converts a binary number to decimal

read -p "Enter a binary number: " binary

# Validate input: only 0s and 1s
if [[ ! $binary =~ ^[01]+$ ]]; then
    echo "Error: Input must be a binary number (only 0s and 1s)."
    exit 1
fi

decimal=0
length=${#binary}

# Loop through each bit
for (( i=0; i<length; i++ )); do
    bit=${binary:$i:1}
    power=$((length - i - 1))
    decimal=$((decimal + bit * (2 ** power)))
done

echo "Decimal: $decimal"
