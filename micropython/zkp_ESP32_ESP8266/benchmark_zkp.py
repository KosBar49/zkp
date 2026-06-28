#!/usr/bin/env python3
"""
Benchmark script for running ZKP implementations on ESP32 and ESP8266
Captures timing data and saves to CSV for analysis
"""

import subprocess
import csv
import re
import os
from pathlib import Path
from datetime import datetime

# Device configuration
DEVICES = {
    'ESP32': {'port': '/dev/ttyUSB1'},
    'ESP8266': {'port': '/dev/ttyUSB0'}
}

# Output CSV file
OUTPUT_CSV = 'zkp_benchmark_results.csv'

# Timeout in seconds (increased for complex operations)
TIMEOUT_SECONDS = 300  # 5 minutes

def find_zkp_files():
    """Find all ZKP Python implementation files"""
    zkp_files = []

    # Directories to search
    directories = [
        'log_discrete',
        'log_equality',
        'log_conjunction',
        'log_disjunction',
        'pedersen_commitment',
        'pederesen_commitment_messages',
        'pederesen_commitments'
    ]

    for directory in directories:
        dir_path = Path(directory)
        if dir_path.exists():
            # Find all .py files except ecc.py (library files)
            for py_file in dir_path.glob('*.py'):
                if py_file.name != 'ecc.py':
                    zkp_files.append({
                        'path': str(py_file),
                        'protocol': directory,
                        'variant': py_file.stem
                    })

    return zkp_files

def run_zkp_on_device(file_path, device_name, port):
    """Run a ZKP script on a device using ampy and capture output"""
    try:
        print(f"  Running on {device_name} ({port})...", end=' ', flush=True)

        # Run ampy command
        cmd = ['ampy', '--port', port, 'run', file_path]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS
        )

        output = result.stdout + result.stderr

        # Parse timing data from output
        verify_time = None
        response_time = None

        # Look for patterns like "time of verify: 123.456"
        verify_match = re.search(r'time of verify:\s*([\d.]+)', output)
        response_match = re.search(r'time of response:\s*([\d.]+)', output)

        if verify_match:
            verify_time = float(verify_match.group(1))
        if response_match:
            response_time = float(response_match.group(1))

        # Check for errors
        error = None
        if result.returncode != 0:
            error = output[:200]  # First 200 chars of error
        elif 'Error' in output or 'Traceback' in output:
            error = "Runtime error"

        print("✓" if not error else "✗")

        return {
            'verify_time': verify_time,
            'response_time': response_time,
            'error': error,
            'raw_output': output
        }

    except subprocess.TimeoutExpired:
        print(f"✗ (timeout after {TIMEOUT_SECONDS}s)")
        return {
            'verify_time': None,
            'response_time': None,
            'error': f'Timeout after {TIMEOUT_SECONDS}s',
            'raw_output': ''
        }
    except Exception as e:
        print(f"✗ ({str(e)})")
        return {
            'verify_time': None,
            'response_time': None,
            'error': str(e),
            'raw_output': ''
        }

def main():
    print("=" * 70)
    print("ZKP Benchmark Script for ESP32/ESP8266")
    print("=" * 70)
    print(f"Timeout: {TIMEOUT_SECONDS} seconds per test")
    print()

    # Find all ZKP files
    print("Finding ZKP implementation files...")
    zkp_files = find_zkp_files()
    print(f"Found {len(zkp_files)} ZKP implementations\n")

    if not zkp_files:
        print("No ZKP files found!")
        return

    # Prepare CSV output
    csv_file = open(OUTPUT_CSV, 'w', newline='')
    csv_writer = csv.DictWriter(csv_file, fieldnames=[
        'timestamp',
        'protocol',
        'variant',
        'file_path',
        'device',
        'port',
        'verify_time_us',
        'response_time_us',
        'total_time_us',
        'error',
        'raw_output'
    ])
    csv_writer.writeheader()

    # Run benchmarks
    total_runs = len(zkp_files) * len(DEVICES)
    current_run = 0

    for zkp_file in zkp_files:
        print(f"\n[{zkp_file['protocol']}] {zkp_file['variant']}")
        print(f"  File: {zkp_file['path']}")

        for device_name, device_config in DEVICES.items():
            current_run += 1
            print(f"  [{current_run}/{total_runs}] ", end='')

            result = run_zkp_on_device(
                zkp_file['path'],
                device_name,
                device_config['port']
            )

            # Calculate total time
            total_time = None
            if result['verify_time'] and result['response_time']:
                total_time = result['verify_time'] + result['response_time']

            # Write to CSV
            csv_writer.writerow({
                'timestamp': datetime.now().isoformat(),
                'protocol': zkp_file['protocol'],
                'variant': zkp_file['variant'],
                'file_path': zkp_file['path'],
                'device': device_name,
                'port': device_config['port'],
                'verify_time_us': result['verify_time'],
                'response_time_us': result['response_time'],
                'total_time_us': total_time,
                'error': result['error'],
                'raw_output': result['raw_output']
            })
            csv_file.flush()  # Write immediately

    csv_file.close()

    print("\n" + "=" * 70)
    print(f"Benchmark complete! Results saved to: {OUTPUT_CSV}")
    print("=" * 70)

    # Print summary
    print("\nSummary:")
    print(f"  Total implementations tested: {len(zkp_files)}")
    print(f"  Devices tested: {len(DEVICES)}")
    print(f"  Total runs: {total_runs}")
    print(f"\nResults saved to: {os.path.abspath(OUTPUT_CSV)}")

if __name__ == '__main__':
    main()
