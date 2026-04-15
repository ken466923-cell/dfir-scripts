# Forensic Timeline Generator
# Converts any CSV with timestamps into a sortable timeline

import csv
import os
from datetime import datetime

def create_timeline(input_csv, output_txt):
    events = []
    
    with open(input_csv, 'r') as file:
        reader = csv.DictReader(file)
        
        # Look for any column that might contain a timestamp
        time_columns = [col for col in reader.fieldnames 
                       if any(keyword in col.lower() for keyword in 
                       ['time', 'date', 'accessed', 'modified', 'created', 'timestamp'])]
        
        if not time_columns:
            print("No timestamp columns found. Using first column as fallback.")
            time_columns = [reader.fieldnames[0]]
        
        for row in reader:
            for time_col in time_columns:
                time_str = row.get(time_col, '')
                if time_str and time_str != 'N/A':
                    events.append(f"[{time_str}] {row}")
                    break
    
    # Sort events chronologically
    events.sort()
    
    with open(output_txt, 'w') as out:
        out.write("=== FORENSIC TIMELINE ===\n")
        out.write(f"Source: {input_csv}\n")
        out.write(f"Total events: {len(events)}\n")
        out.write("=" * 60 + "\n\n")
        for event in events:
            out.write(event + "\n")
    
    print(f"✓ Timeline created: {output_txt}")
    print(f"✓ {len(events)} events sorted chronologically")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python 04-csv-timeline.py <filename.csv>")
        print("Example: python 04-csv-timeline.py usb_history.csv")
        sys.exit(1)
    
    input_file = sys.argv[1]
    if not os.path.exists(input_file):
        print(f"Error: File not found - {input_file}")
        sys.exit(1)
    
    output_file = input_file.replace('.csv', '_timeline.txt')
    create_timeline(input_file, output_file)
