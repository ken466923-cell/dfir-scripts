# Phishing Email Header Analyzer
# Extracts source IP, SPF, DKIM, and routing path

import re
import sys
import os

def parse_email_headers(header_text):
    """Extract key forensic artifacts from email headers"""
    
    artifacts = {
        'from_address': None,
        'return_path': None,
        'source_ips': [],
        'received_servers': [],
        'spf_result': None,
        'dkim_result': None,
        'authentication_results': None,
        'subject': None,
        'date': None
    }
    
    # Extract From address
    from_match = re.search(r'From:.*?([\w\.-]+@[\w\.-]+\.\w+)', header_text, re.IGNORECASE)
    if from_match:
        artifacts['from_address'] = from_match.group(1)
    
    # Extract Return-Path
    return_match = re.search(r'Return-Path:.*?([\w\.-]+@[\w\.-]+\.\w+)', header_text, re.IGNORECASE)
    if return_match:
        artifacts['return_path'] = return_match.group(1)
    
    # Extract all source IPs from Received headers
    ip_pattern = r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]'
    all_ips = re.findall(ip_pattern, header_text)
    artifacts['source_ips'] = list(dict.fromkeys(all_ips))
    
    # Extract Received servers
    server_pattern = r'by\s+([\w\.-]+)'
    servers = re.findall(server_pattern, header_text)
    artifacts['received_servers'] = servers[:5]
    
    # Extract SPF/DKIM results
    spf_match = re.search(r'spf=(pass|fail|neutral|none)', header_text, re.IGNORECASE)
    if spf_match:
        artifacts['spf_result'] = spf_match.group(1)
    
    dkim_match = re.search(r'dkim=(pass|fail|neutral|none)', header_text, re.IGNORECASE)
    if dkim_match:
        artifacts['dkim_result'] = dkim_match.group(1)
    
    # Extract Subject
    subject_match = re.search(r'Subject:\s*(.+?)(?:\n|$)', header_text, re.IGNORECASE)
    if subject_match:
        artifacts['subject'] = subject_match.group(1).strip()
    
    # Extract Date
    date_match = re.search(r'Date:\s*(.+?)(?:\n|$)', header_text, re.IGNORECASE)
    if date_match:
        artifacts['date'] = date_match.group(1).strip()
    
    return artifacts

def main():
    print("=" * 60)
    print("PHISHING EMAIL HEADER ANALYZER")
    print("=" * 60)
    
    header_text = None
    
    if len(sys.argv) >= 2:
        # Read from file
        with open(sys.argv[1], 'r') as f:
            header_text = f.read()
    else:
        # Read from stdin (paste headers)
        print("\nPaste email headers below. Press Ctrl+Z then Enter when done:\n")
        lines = []
        try:
            while True:
                line = input()
                lines.append(line)
        except EOFError:
            pass
        header_text = '\n'.join(lines)
    
    if not header_text or len(header_text.strip()) < 10:
        print("Error: No valid email headers provided")
        sys.exit(1)
    
    results = parse_email_headers(header_text)
    
    print("\n=== FORENSIC ANALYSIS RESULTS ===")
    print(f"From Address:      {results['from_address']}")
    print(f"Return-Path:       {results['return_path']}")
    print(f"Subject:           {results['subject']}")
    print(f"Date:              {results['date']}")
    print(f"\nSource IPs Found:  {', '.join(results['source_ips']) if results['source_ips'] else 'None'}")
    print(f"SPF Result:        {results['spf_result'] or 'Not found'}")
    print(f"DKIM Result:       {results['dkim_result'] or 'Not found'}")
    
    if results['source_ips']:
        print(f"\n[!] Suspicious Source IP: {results['source_ips'][0]}")
        print(f"    Investigate this IP in VirusTotal or AbuseIPDB")
    
    # Save report
    with open("phishing_analysis_report.txt", "w") as report:
        report.write(f"=== Phishing Analysis Report ===\n")
        for key, value in results.items():
            report.write(f"{key}: {value}\n")
    print(f"\n✓ Full report saved to phishing_analysis_report.txt")

if __name__ == "__main__":
    main()
