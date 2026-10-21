Scripts in This Repository

| Script | What It Does |
|--------|---------------|
| `01-usb-history.ps1` | Shows every USB drive ever connected to a Windows computer |
| `02-recent-files.ps1` | Lists recently opened files and downloads |
| `03-eventlog-failed-logins.ps1` | Finds brute force attempts (requires Admin) |
| `04-csv-timeline.py` | Creates chronological timeline from CSV evidence |
| `05-hash-verifier.py` | Calculates MD5/SHA256 hashes for evidence integrity |
| `06-phishing-header-parser.py` | Traces real source IP of phishing emails |

## How to Run

### PowerShell Scripts (Windows)
```powershell
.\01-usb-history.ps1
.\02-recent-files.ps1
.\03-eventlog-failed-logins.ps1  # Run as Administrator
