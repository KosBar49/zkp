#!/bin/bash
# Quick script to check benchmark progress

echo "=== Benchmark Progress ==="
echo ""

if [ -f "zkp_benchmark_results.csv" ]; then
    total_lines=$(wc -l < zkp_benchmark_results.csv)
    results=$((total_lines - 1))  # Subtract header
    echo "Total results collected: $results"
    echo ""

    # Count successful vs failed
    successful=$(awk -F',' 'NR>1 && $9!="" && $9!="None" {count++} END {print count+0}' zkp_benchmark_results.csv)
    failed=$(awk -F',' 'NR>1 && ($9=="" || $9=="None") {count++} END {print count+0}' zkp_benchmark_results.csv)

    echo "Successful tests: $successful"
    echo "Failed tests: $failed"
    echo ""

    # Show last few entries
    echo "=== Last 5 Results ==="
    tail -5 zkp_benchmark_results.csv | cut -d',' -f2,3,5,9,10 | column -t -s','
else
    echo "No results file found yet."
fi
