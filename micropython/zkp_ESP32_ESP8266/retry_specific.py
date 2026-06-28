#!/usr/bin/env python3
"""
Retry specific ZKP implementation on both devices
"""

import subprocess
import csv
import re
import sys
from datetime import datetime
from pathlib import Path

# Device configuration
DEVICES = {
    'ESP32': {'port': '/dev/ttyUSB1'},
    'ESP8266': {'port': '/dev/ttyUSB0'}
}

OUTPUT_CSV = 'zkp_benchmark_results.csv'
TIMEOUT_SECONDS = 300  # 5 minutes

def run_zkp_on_device(file_path, device_name, port, run_number=1):
    """Run a ZKP script on a device using ampy and capture output"""
    try:
        print(f"  Run #{run_number} on {device_name} ({port})...", end=' ', flush=True)

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
    if len(sys.argv) < 2:
        print("Usage: python3 retry_specific.py <file_path> [num_runs]")
        print("Example: python3 retry_specific.py log_disjunction/zkp_log_disjunction_ecc.py 3")
        sys.exit(1)

    file_path = sys.argv[1]
    num_runs = int(sys.argv[2]) if len(sys.argv) > 2 else 1

    if not Path(file_path).exists():
        print(f"Error: File not found: {file_path}")
        sys.exit(1)

    # Extract protocol and variant from path
    parts = file_path.split('/')
    protocol = parts[0] if len(parts) > 1 else 'unknown'
    variant = Path(file_path).stem

    print("=" * 70)
    print(f"Retry Benchmark for Specific ZKP Implementation")
    print("=" * 70)
    print(f"File: {file_path}")
    print(f"Protocol: {protocol}")
    print(f"Variant: {variant}")
    print(f"Number of runs per device: {num_runs}")
    print(f"Timeout: {TIMEOUT_SECONDS} seconds per test")
    print()

    # Prepare to append to CSV
    csv_exists = Path(OUTPUT_CSV).exists()
    csv_file = open(OUTPUT_CSV, 'a', newline='')
    csv_writer = csv.DictWriter(csv_file, fieldnames=[
        'timestamp',
        'protocol',
        'variant',
        'file_path',
        'device',
        'port',
        'verify_time_s',
        'response_time_s',
        'total_time_s',
        'error',
        'raw_output'
    ])

    # Write header only if creating new file
    if not csv_exists:
        csv_writer.writeheader()

    results_summary = {}

    # Run benchmarks
    for device_name, device_config in DEVICES.items():
        print(f"\n{device_name}:")
        device_results = []

        for run_num in range(1, num_runs + 1):
            result = run_zkp_on_device(
                file_path,
                device_name,
                device_config['port'],
                run_num
            )

            # Convert times from microseconds to seconds
            verify_time_s = result['verify_time'] / 1_000_000 if result['verify_time'] else None
            response_time_s = result['response_time'] / 1_000_000 if result['response_time'] else None

            # Calculate total time
            total_time_s = None
            if verify_time_s and response_time_s:
                total_time_s = verify_time_s + response_time_s
                device_results.append(total_time_s)
                print(f"    Total time: {total_time_s:.3f} seconds")

            # Write to CSV
            csv_writer.writerow({
                'timestamp': datetime.now().isoformat(),
                'protocol': protocol,
                'variant': variant,
                'file_path': file_path,
                'device': device_name,
                'port': device_config['port'],
                'verify_time_s': f"{verify_time_s:.6f}" if verify_time_s else '',
                'response_time_s': f"{response_time_s:.6f}" if response_time_s else '',
                'total_time_s': f"{total_time_s:.6f}" if total_time_s else '',
                'error': result['error'],
                'raw_output': result['raw_output']
            })
            csv_file.flush()

        if device_results:
            avg_time = sum(device_results) / len(device_results)
            min_time = min(device_results)
            max_time = max(device_results)
            results_summary[device_name] = {
                'avg': avg_time,
                'min': min_time,
                'max': max_time,
                'count': len(device_results)
            }
            print(f"  Average: {avg_time:.3f}s, Min: {min_time:.3f}s, Max: {max_time:.3f}s")

    csv_file.close()

    print("\n" + "=" * 70)
    print("Retry benchmark complete!")
    print("=" * 70)

    # Print comparison
    if 'ESP32' in results_summary and 'ESP8266' in results_summary:
        print("\nComparison:")
        esp32_avg = results_summary['ESP32']['avg']
        esp8266_avg = results_summary['ESP8266']['avg']
        speedup = esp8266_avg / esp32_avg
        print(f"  ESP32 average:   {esp32_avg:.3f}s")
        print(f"  ESP8266 average: {esp8266_avg:.3f}s")
        print(f"  Speedup: {speedup:.2f}x (ESP32 is {speedup:.2f}x faster)" if speedup > 1 else f"  ESP8266 is {1/speedup:.2f}x faster")

    print(f"\nResults appended to: {OUTPUT_CSV}")

if __name__ == '__main__':
    main()
