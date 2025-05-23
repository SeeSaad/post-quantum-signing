#!/bin/bash
sum=0
runs=30

for i in $(seq 1 $runs); do
    start=$(date +%s%N)
    ./keygen
    end=$(date +%s%N)
    rm public_key.bin secret_key.bin

    duration=$((end - start))  # nanoseconds
    echo "Run $i: $duration ns"

    sum=$((sum + duration))
done

avg=$((sum / runs))
echo "Average time over $runs runs: $avg ns"

ms=$(echo "scale=3; $avg / 1000000" | bc)
echo "Average time: ($ms ms)"
