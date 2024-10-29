#!/bin/sh

# Check if a variant argument was provided
if [ -z "$1" ]; then
    echo "Usage: $0 <variant>"
    exit 1
fi

VARIANT=$1

# Run the command 10 times and extract times
for i in $(seq 1 10); do
    # Run the make command with the specified variant and capture the output, suppressing warnings
    output=$(make all-$VARIANT 2>/dev/null && ./Additional_Implementations/$VARIANT/api_test 2>/dev/null)

    # Extract the times for sign and verify from the output
    sign_time=$(echo "$output" | grep "Time taken to open:" | sed -E 's/.*Time taken to open: ([0-9.]+) seconds.*/\1/')
    verify_time=$(echo "$output" | grep "Time taken to commit:" | sed -E 's/.*Time taken to commit: ([0-9.]+) seconds.*/\1/')

    # Print the times, check if values are empty and handle errors
    if [ -n "$sign_time" ] && [ -n "$verify_time" ]; then
        echo "$sign_time $verify_time"
    else
        echo "Run $i: Error capturing times. Output was:"
        echo "$output"
    fi    
done
