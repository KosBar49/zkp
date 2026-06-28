#!/usr/bin/env python3
"""
Analysis script for ZKP benchmark results
Reads the CSV file and provides statistical summary
"""

import csv
import pandas as pd
from pathlib import Path

CSV_FILE = 'zkp_benchmark_results.csv'

def analyze_results():
    """Analyze benchmark results from CSV"""

    if not Path(CSV_FILE).exists():
        print(f"Error: {CSV_FILE} not found!")
        print("Run benchmark_zkp.py first to generate results.")
        return

    # Read CSV
    df = pd.read_csv(CSV_FILE)

    print("=" * 80)
    print("ZKP Benchmark Results Analysis")
    print("=" * 80)
    print()

    # Overall statistics
    print(f"Total runs: {len(df)}")
    print(f"Successful runs: {df['error'].isna().sum()}")
    print(f"Failed runs: {df['error'].notna().sum()}")
    print()

    # Filter successful runs
    df_success = df[df['error'].isna()].copy()

    if len(df_success) == 0:
        print("No successful runs to analyze!")
        return

    # Check if times are in seconds or microseconds
    if 'verify_time_s' in df.columns:
        # Times are already in seconds
        df_success['verify_time_s'] = pd.to_numeric(df_success['verify_time_s'], errors='coerce')
        df_success['response_time_s'] = pd.to_numeric(df_success['response_time_s'], errors='coerce')
        df_success['total_time_s'] = pd.to_numeric(df_success['total_time_s'], errors='coerce')
    else:
        # Times are in microseconds, convert to seconds
        df_success['verify_time_s'] = df_success['verify_time_us'] / 1000000
        df_success['response_time_s'] = df_success['response_time_us'] / 1000000
        df_success['total_time_s'] = df_success['total_time_us'] / 1000000

    # Summary by device
    print("\n" + "=" * 80)
    print("Performance by Device")
    print("=" * 80)
    for device in df_success['device'].unique():
        device_data = df_success[df_success['device'] == device]
        print(f"\n{device}:")
        print(f"  Average verify time:   {device_data['verify_time_s'].mean():.3f} s")
        print(f"  Average response time: {device_data['response_time_s'].mean():.3f} s")
        print(f"  Average total time:    {device_data['total_time_s'].mean():.3f} s")
        print(f"  Min total time:        {device_data['total_time_s'].min():.3f} s")
        print(f"  Max total time:        {device_data['total_time_s'].max():.3f} s")

    # Summary by protocol
    print("\n" + "=" * 80)
    print("Performance by Protocol")
    print("=" * 80)
    for protocol in sorted(df_success['protocol'].unique()):
        protocol_data = df_success[df_success['protocol'] == protocol]
        print(f"\n{protocol}:")
        print(f"  Implementations: {len(protocol_data['variant'].unique())}")
        print(f"  Avg total time:  {protocol_data['total_time_s'].mean():.3f} s")
        print(f"  Min total time:  {protocol_data['total_time_s'].min():.3f} s")
        print(f"  Max total time:  {protocol_data['total_time_s'].max():.3f} s")

    # Detailed comparison: ESP32 vs ESP8266
    print("\n" + "=" * 80)
    print("ESP32 vs ESP8266 Comparison (by variant)")
    print("=" * 80)
    print(f"{'Variant':<40} {'ESP32 (s)':<15} {'ESP8266 (s)':<15} {'Speedup':<10}")
    print("-" * 80)

    variants = df_success.groupby('variant')
    for variant_name, variant_data in variants:
        esp32_time = variant_data[variant_data['device'] == 'ESP32']['total_time_s'].mean()
        esp8266_time = variant_data[variant_data['device'] == 'ESP8266']['total_time_s'].mean()

        if pd.notna(esp32_time) and pd.notna(esp8266_time) and esp8266_time > 0:
            speedup = esp8266_time / esp32_time
            print(f"{variant_name:<40} {esp32_time:>12.3f}   {esp8266_time:>12.3f}   {speedup:>8.2f}x")

    # Errors summary
    if len(df[df['error'].notna()]) > 0:
        print("\n" + "=" * 80)
        print("Errors")
        print("=" * 80)
        error_counts = df[df['error'].notna()].groupby(['device', 'variant', 'error']).size()
        for (device, variant, error), count in error_counts.items():
            print(f"{device} - {variant}: {error} ({count} times)")

    print("\n" + "=" * 80)

if __name__ == '__main__':
    try:
        analyze_results()
    except ImportError:
        print("Error: pandas is required for analysis")
        print("Install with: pip install pandas")
        print("\nAlternatively, you can view the raw data in: " + CSV_FILE)
