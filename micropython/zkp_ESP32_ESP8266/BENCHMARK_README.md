# ZKP Benchmark Scripts

## Overview

These scripts automate the benchmarking of all Zero Knowledge Proof implementations on ESP32 and ESP8266 devices.

## Prerequisites

1. **Hardware Setup:**
   - ESP32 connected to `/dev/ttyUSB1`
   - ESP8266 connected to `/dev/ttyUSB0`
   - Both devices should have MicroPython installed

2. **Software Requirements:**
   ```bash
   pip install adafruit-ampy pandas
   ```

## Scripts

### 1. `benchmark_zkp.py` - Main Benchmark Script

Runs all ZKP implementations on both devices and captures timing data.

**Usage:**
```bash
python3 benchmark_zkp.py
```

**What it does:**
- Automatically finds all ZKP `.py` files in subdirectories
- Runs each implementation on both ESP32 and ESP8266 using `ampy`
- Captures timing output (verify time, response time)
- Saves results to `zkp_benchmark_results.csv`
- Shows progress in real-time

**Output CSV Columns:**
- `timestamp` - When the test was run
- `protocol` - Protocol type (e.g., log_discrete, pedersen_commitment)
- `variant` - Implementation variant (e.g., zkp_log_discrete_ni)
- `file_path` - Path to the source file
- `device` - Device name (ESP32 or ESP8266)
- `port` - Serial port used
- `verify_time_us` - Verification time in microseconds
- `response_time_us` - Response generation time in microseconds
- `total_time_us` - Total time (verify + response)
- `error` - Error message if run failed
- `raw_output` - Complete output from the device

### 2. `analyze_results.py` - Results Analysis Script

Analyzes the benchmark results and generates statistical summary.

**Usage:**
```bash
python3 analyze_results.py
```

**What it shows:**
- Overall success/failure statistics
- Performance by device (ESP32 vs ESP8266)
- Performance by protocol type
- Detailed comparison showing speedup between devices
- Error summary

## Example Workflow

1. **Connect devices:**
   ```bash
   # Check devices are connected
   ls -l /dev/ttyUSB*
   ```

2. **Run benchmark:**
   ```bash
   python3 benchmark_zkp.py
   ```

3. **Analyze results:**
   ```bash
   python3 analyze_results.py
   ```

4. **View raw data:**
   ```bash
   # Open CSV in spreadsheet
   libreoffice zkp_benchmark_results.csv

   # Or view in terminal
   column -t -s, zkp_benchmark_results.csv | less -S
   ```

## Customization

### Modify Device Configuration

Edit `benchmark_zkp.py` and change the `DEVICES` dictionary:

```python
DEVICES = {
    'ESP32': {'port': '/dev/ttyUSB1'},
    'ESP8266': {'port': '/dev/ttyUSB0'}
}
```

### Run Specific Protocols Only

Modify the `directories` list in `find_zkp_files()`:

```python
directories = [
    'log_discrete',
    'pedersen_commitment',
    # Comment out protocols you don't want to test
]
```

### Adjust Timeout

Change the timeout value in `run_zkp_on_device()`:

```python
result = subprocess.run(
    cmd,
    capture_output=True,
    text=True,
    timeout=120  # Increase to 120 seconds if needed
)
```

## Troubleshooting

### Device Not Found
```
Error: could not find device
```
**Solution:** Check device connections and port names:
```bash
ls -l /dev/ttyUSB*
dmesg | tail -20  # Check kernel messages
```

### Permission Denied
```
Error: [Errno 13] Permission denied: '/dev/ttyUSB0'
```
**Solution:** Add user to dialout group:
```bash
sudo usermod -a -G dialout $USER
# Log out and log back in
```

### Timeout Errors
**Solution:**
- Increase timeout in `benchmark_zkp.py`
- Check if device is responsive: `ampy --port /dev/ttyUSB1 ls`
- Press reset button on device

### Import Errors on Device
**Solution:**
- Ensure all required files are on the device
- For ECC variants, make sure `ecc.py` is uploaded to the device:
  ```bash
  ampy --port /dev/ttyUSB1 put log_equality/ecc.py
  ```

## Output Example

```
======================================================================
ZKP Benchmark Script for ESP32/ESP8266
======================================================================

Finding ZKP implementation files...
Found 23 ZKP implementations

[log_discrete] zkp_log_discrete
  File: log_discrete/zkp_log_discrete.py
  [1/46] Running on ESP32 (/dev/ttyUSB1)... ✓
  [2/46] Running on ESP8266 (/dev/ttyUSB0)... ✓

[log_discrete] zkp_log_discrete_ni
  File: log_discrete/zkp_log_discrete_ni.py
  [3/46] Running on ESP32 (/dev/ttyUSB1)... ✓
  [4/46] Running on ESP8266 (/dev/ttyUSB0)... ✓

...

======================================================================
Benchmark complete! Results saved to: zkp_benchmark_results.csv
======================================================================
```

## Notes

- Each run takes approximately 2-3 minutes per device per implementation
- Total benchmark time depends on number of implementations
- The script continues even if individual tests fail
- Results are written incrementally (safe to Ctrl+C if needed)
- Timestamps allow tracking multiple benchmark runs over time
