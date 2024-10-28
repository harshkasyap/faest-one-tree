#!/bin/bash

# Check if the target argument was provided
if [ -z "$1" ]; then
    echo "Usage: $0 <target> '[benchmark_name]'"
    exit 1
fi

TARGET=$1
BENCH_NAME=${2:-'[mybench]'}  # Use '[mybench]' as the default if no second argument is given

# Run the make command with the specified target and check for success
if make "all-$TARGET"; then
    # Run the benchmark with the provided or default benchmark name if make succeeds
    "./Additional_Implementations/$TARGET/${TARGET}_bench" "$BENCH_NAME"
else
    echo "Make command failed for target $TARGET."
    exit 1
fi
