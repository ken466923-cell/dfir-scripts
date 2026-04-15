# Forensic File Hash Calculator
# MD5, SHA1, SHA256 for evidence integrity verification

import hashlib
import os
import sys
from datetime import datetime

def calculate_hashes(filepath):
    """Calculate MD5, SHA1, and SHA256 hashes of a file"""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    
    try:
        with open(filepath, 'rb') as f:
            # Read in chunks for large files
            for chunk in iter(lambda: f.read(4096), b''):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        
        return {
            'filename': os.path.basename(filepath),
            'md5': md5.hexdigest(),
            'sha1': sha1.hexdigest(),
            'sha256': sha256.hexdigest(),
            'size_bytes': os.path.getsize(filepath),
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        return {'error': str(e), 'filename': filepath}

def main():
    print("=" * 60)
    print("FORENSIC FILE HASH VERIFIER")
    print("=" * 60)
    
    if len(sys.argv) < 2:
        print("Usage: python 05-hash-verifier.py <filename>")
        print("Example: python 05-hash-verifier.py C:\\Windows\\System32\\notepad.exe")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    if not os.path.exists(filepath):
        print(f"Error: File not found - {filepath}")
        sys.exit(1)
    
    results = calculate_hashes(filepath)
    
    if 'error' in results:
        print(f"Error: {results['error']}")
    else:
        print(f"\nFile: {results['filename']}")
        print(f"Size: {results['size_bytes']} bytes")
        print(f"MD5:    {results['md5']}")
        print(f"SHA1:   {results['sha1']}")
        print(f"SHA256: {results['sha256']}")
        print(f"Time:   {results['timestamp']}")
        
        # Save to hash log
        with open("hash_manifest.txt", "a") as log:
            log.write(f"{results['timestamp']} | {results['filename']} | MD5:{results['md5']}\n")
        print("\n✓ Hash saved to hash_manifest.txt")

if __name__ == "__main__":
    main()
