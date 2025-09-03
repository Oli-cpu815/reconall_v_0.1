# ReconAll - Comprehensive Reconnaissance Tool

![ReconAll Banner](https://img.shields.io/badge/Status-Active-green)

## Overview
**ReconAll** is a powerful Python-based reconnaissance tool designed for ethical hackers, penetration testers, and cybersecurity enthusiasts. It performs an extensive scan of a target domain, gathering detailed information from DNS records, WHOIS data, subdomains, directories, headers, SSL/TLS info, WAF detection, and more. Results are saved in both JSON and structured text formats for easy analysis.

---

## Features
- WHOIS lookup
- DNS record enumeration (A, MX, NS, TXT)
- Subdomain enumeration (including Sublist3r integration)
- HTTP header collection
- Common and hidden directory scanning
- WaybackURLs fetching and filtering
- WhatWeb technology detection
- WAF detection using Nmap scripts
- SSL/TLS certificate information
- Nmap port scanning
- Shodan host information (API required)
- Rich terminal interface with color-coded status messages
- Output reports in JSON and structured text format

---

## Requirements
- Python 3.8 or higher
- Required Python packages:
  - `requests`
  - `rich`
  - `dnspython`
  - `shodan` (optional for Shodan scans)
- External tools (optional but recommended for full functionality):
  - `sublist3r`
  - `nmap`
  - `whatweb`
  - `waybackurls`

---

## Installation
1. Clone the repository:
    ```bash
    git clone https://github.com/Oli-cpu815/reconall_v_0.1.git
    cd reconall_v_0.1
    ```

2. Make the main script executable:
    ```bash
    sudo chmod +x *
    ```

3. Create a virtual environment and install dependencies:
    ```bash
    ./setup.sh

    ```

---

## Usage
1. Run the tool:
    ```bash
    python3 reconall.py
    ```
2. Enter the target domain when prompted (e.g., `example.com`).
3. Wait while ReconAll performs the scans. Status messages will appear in the terminal.
4. After completion, check the `outputs/` folder for:
   - `reconall_report.json` → JSON formatted results
   - `reconall_report.txt` → Human-readable formatted report

---

## Configuration
- **Shodan API**: Replace `SHODAN_API_KEY` in the script with your own API key for Shodan scans:
    ```python
    SHODAN_API_KEY = "YOUR_API_KEY_HERE"
    ```

---

## Notes
- Ensure external tools like `nmap`, `sublist3r`, `whatweb`, and `waybackurls` are installed for full functionality.
- Some scans may take several minutes depending on target size and network conditions.
- This tool is intended for **ethical hacking and educational purposes only**. Unauthorized scanning may be illegal.

---

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Author
**Oli Ahamed** – Cybersecurity Analyst, Red Teaming & Ethical Hacking  
- GitHub: [Oli-cpu815](https://github.com/Oli-cpu815)  
- LinkedIn: [Oli Ahamed](https://www.linkedin.com/in/oli-ahamed-forhad/)  
- Email: oliahamed9030@gmail.com
