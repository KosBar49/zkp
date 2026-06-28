#!/usr/bin/env python3
"""
Retry benchmark script for running failed/missing ZKP tests
Increases timeout and only reruns tests without successful data
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

# Increased timeout for slower operations
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

def load_existing_results():
    """Load existing benchmark results from CSV"""
    existing = {}

    if not Path(OUTPUT_CSV).exists():
        print(f"No existing results found ({OUTPUT_CSV})")
        return existing

    try:
        with open(OUTPUT_CSV, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Create unique key for each test
                key = (row['variant'], row['device'])

                # Check if this run was successful (has timing data and no error)
                is_successful = (
                    row['verify_time_us'] and
                    row['response_time_us'] and
                    row['verify_time_us'] != '' and
                    row['response_time_us'] != '' and
                    (not row['error'] or row['error'] == '')
                )

                # Only store if successful (we want to retry failed ones)
                if is_successful:
                    existing[key] = row

        print(f"Loaded {len(existing)} successful results from existing CSV")
    except Exception as e:
        print(f"Warning: Could not load existing results: {e}")

    return existing

def run_zkp_on_device(file_path, device_name, port):
    """Run a ZKP script on a device using ampy and capture output"""
    try:
        print(f"  Running on {device_name} ({port})...", end=' ', flush=True)

        # Run ampy command with increased timeout
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
    print("ZKP Benchmark Retry Script (Increased Timeout)")
    print("=" * 70)
    print(f"Timeout: {TIMEOUT_SECONDS} seconds per test")
    print()

    # Load existing results
    print("Checking for existing results...")
    existing_results = load_existing_results()
    print()

    # Find all ZKP files
    print("Finding ZKP implementation files...")
    zkp_files = find_zkp_files()
    print(f"Found {len(zkp_files)} ZKP implementations\n")

    if not zkp_files:
        print("No ZKP files found!")
        return

    # Determine what needs to be run
    tests_to_run = []
    for zkp_file in zkp_files:
        for device_name, device_config in DEVICES.items():
            key = (zkp_file['variant'], device_name)
            if key not in existing_results:
                tests_to_run.append({
                    'zkp_file': zkp_file,
                    'device_name': device_name,
                    'device_config': device_config
                })

    print(f"Tests already completed successfully: {len(existing_results)}")
    print(f"Tests to run/retry: {len(tests_to_run)}\n")

    if len(tests_to_run) == 0:
        print("All tests have successful results! Nothing to retry.")
        return

    # Determine if we need to create new file or append
    file_exists = Path(OUTPUT_CSV).exists()
    mode = 'a' if file_exists else 'w'

    # Open CSV for appending
    csv_file = open(OUTPUT_CSV, mode, newline='')
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

    # Write header only if creating new file
    if not file_exists:
        csv_writer.writeheader()

    # Run benchmarks for missing/failed tests
    total_runs = len(tests_to_run)
    current_run = 0
    successful = 0
    failed = 0

    for test in tests_to_run:
        zkp_file = test['zkp_file']
        device_name = test['device_name']
        device_config = test['device_config']

        current_run += 1

        print(f"\n[{current_run}/{total_runs}] [{zkp_file['protocol']}] {zkp_file['variant']}")
        print(f"  File: {zkp_file['path']}")
        print(f"  ", end='')

        result = run_zkp_on_device(
            zkp_file['path'],
            device_name,
            device_config['port']
        )

        # Calculate total time
        total_time = None
        if result['verify_time'] and result['response_time']:
            total_time = result['verify_time'] + result['response_time']
            successful += 1
        else:
            failed += 1

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
    print(f"Retry benchmark complete! Results saved to: {OUTPUT_CSV}")
    print("=" * 70)

    # Print summary
    print("\nSummary:")
    print(f"  Tests already successful: {len(existing_results)}")
    print(f"  Tests attempted: {total_runs}")
    print(f"  Newly successful: {successful}")
    print(f"  Still failing: {failed}")
    print(f"\nResults saved to: {os.path.abspath(OUTPUT_CSV)}")

if __name__ == '__main__':
    main()
