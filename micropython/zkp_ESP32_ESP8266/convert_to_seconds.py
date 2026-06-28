#!/usr/bin/env python3
"""
Convert timing values from microseconds to seconds in the CSV file
"""

import csv
from pathlib import Path

CSV_FILE = 'zkp_benchmark_results.csv'
BACKUP_FILE = 'zkp_benchmark_results_before_conversion.csv'

def convert_to_seconds():
    """Convert microsecond values to seconds"""

    if not Path(CSV_FILE).exists():
        print(f"Error: {CSV_FILE} not found!")
        return

    # Backup original file
    import shutil
    shutil.copy(CSV_FILE, BACKUP_FILE)
    print(f"Backup created: {BACKUP_FILE}")

    # Read all rows
    with open(CSV_FILE, 'r') as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        all_rows = list(reader)

    print(f"Total rows: {len(all_rows)}")

    # Update fieldnames (change _us to _s)
    new_fieldnames = []
    for field in fieldnames:
        if field == 'verify_time_us':
            new_fieldnames.append('verify_time_s')
        elif field == 'response_time_us':
            new_fieldnames.append('response_time_s')
        elif field == 'total_time_us':
            new_fieldnames.append('total_time_s')
        else:
            new_fieldnames.append(field)

    # Convert values from microseconds to seconds
    converted_rows = []
    for row in all_rows:
        new_row = {}
        for old_field, new_field in zip(fieldnames, new_fieldnames):
            if old_field in ['verify_time_us', 'response_time_us', 'total_time_us']:
                # Convert from microseconds to seconds
                if row[old_field] and row[old_field] != '':
                    try:
                        value_us = float(row[old_field])
                        value_s = value_us / 1_000_000  # Divide by 10^6
                        new_row[new_field] = f"{value_s:.6f}"
                    except ValueError:
                        new_row[new_field] = ''
                else:
                    new_row[new_field] = ''
            else:
                new_row[new_field] = row[old_field]

        converted_rows.append(new_row)

    # Write converted results
    with open(CSV_FILE, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=new_fieldnames)
        writer.writeheader()
        writer.writerows(converted_rows)

    print(f"\nConversion complete!")
    print(f"Updated file: {CSV_FILE}")
    print(f"Column names updated:")
    print(f"  verify_time_us   -> verify_time_s")
    print(f"  response_time_us -> response_time_s")
    print(f"  total_time_us    -> total_time_s")
    print(f"\nAll time values divided by 1,000,000 (converted to seconds)")

    # Show sample conversion
    print(f"\nSample conversion (first row with data):")
    for row in converted_rows:
        if row['verify_time_s'] and row['verify_time_s'] != '':
            print(f"  Protocol: {row['protocol']} - {row['variant']}")
            print(f"  Device: {row['device']}")
            print(f"  Verify time: {row['verify_time_s']} seconds")
            print(f"  Response time: {row['response_time_s']} seconds")
            print(f"  Total time: {row['total_time_s']} seconds")
            break

if __name__ == '__main__':
    convert_to_seconds()
