#!/usr/bin/env python3
"""
Remove duplicate entries from benchmark results CSV
Keeps the most recent successful result for each (variant, device) pair
"""

import csv
from pathlib import Path

CSV_FILE = 'zkp_benchmark_results.csv'
BACKUP_FILE = 'zkp_benchmark_results_backup.csv'

def deduplicate_results():
    """Remove duplicates, keeping most recent successful result per (variant, device)"""

    if not Path(CSV_FILE).exists():
        print(f"Error: {CSV_FILE} not found!")
        return

    # Backup original file
    Path(CSV_FILE).rename(BACKUP_FILE)
    print(f"Backup created: {BACKUP_FILE}")

    # Read all rows
    with open(BACKUP_FILE, 'r') as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        all_rows = list(reader)

    print(f"Total rows in original file: {len(all_rows)}")

    # Group by (variant, device)
    groups = {}

    for row in all_rows:
        key = (row['variant'], row['device'])

        if key not in groups:
            groups[key] = []

        groups[key].append(row)

    print(f"Unique (variant, device) combinations: {len(groups)}")

    # For each group, select the best row
    deduplicated = []

    for key, rows in groups.items():
        variant, device = key

        # Prioritize successful results (with timing data and no error)
        # Check which column names exist (could be _us or _s)
        verify_col = 'verify_time_s' if 'verify_time_s' in rows[0] else 'verify_time_us'
        response_col = 'response_time_s' if 'response_time_s' in rows[0] else 'response_time_us'

        successful = [r for r in rows if (
            r[verify_col] and
            r[response_col] and
            r[verify_col] != '' and
            r[response_col] != '' and
            (not r['error'] or r['error'] == '')
        )]

        if successful:
            # Keep most recent successful result
            best = successful[-1]
            deduplicated.append(best)
            if len(rows) > 1:
                print(f"  {variant} ({device}): {len(rows)} entries -> kept successful")
        else:
            # No successful results, keep most recent attempt
            best = rows[-1]
            deduplicated.append(best)
            if len(rows) > 1:
                print(f"  {variant} ({device}): {len(rows)} entries -> kept latest failed")

    # Write deduplicated results
    with open(CSV_FILE, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(deduplicated)

    print(f"\nDeduplicated results written to: {CSV_FILE}")
    print(f"Rows after deduplication: {len(deduplicated)}")
    print(f"Rows removed: {len(all_rows) - len(deduplicated)}")

    # Count successful vs failed
    # Check which column names exist
    verify_col = 'verify_time_s' if 'verify_time_s' in fieldnames else 'verify_time_us'
    response_col = 'response_time_s' if 'response_time_s' in fieldnames else 'response_time_us'

    successful_count = sum(1 for r in deduplicated if (
        r[verify_col] and
        r[response_col] and
        r[verify_col] != '' and
        r[response_col] != '' and
        (not r['error'] or r['error'] == '')
    ))

    print(f"\nFinal statistics:")
    print(f"  Successful tests: {successful_count}")
    print(f"  Failed tests: {len(deduplicated) - successful_count}")

if __name__ == '__main__':
    deduplicate_results()
