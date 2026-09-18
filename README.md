# VectorInject - SQL Injection + DB Extractor

![Version](https://img.shields.io/badge/version-1.0.0-red)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)
![Status](https://img.shields.io/badge/status-active-brightgreen)

An advanced SQL Injection detection and database extraction framework written in **Pure Python**. Designed for educational purposes and authorized penetration testing.

---

## Project Information

| Field | Value |
|-------|-------|
| **Author** | Abdulwahab Nashwan Ajlan |
| **Supervisor** | Dr. Ahmed Al-Suraihi |
| **Course** | Cybersecurity Practical Project |
| **Version** | 1.0.0 |
| **Language** | Python 3.8+ (Pure Python - No external libraries) |
| **License** | MIT |

---

## Overview

**VectorInject** is a command-line tool that automates the process of:

1. **Scanning** web applications for potential SQL injection points
2. **Detecting** SQL injection vulnerabilities (Error-based, Boolean-based, Time-based, UNION-based)
3. **Fingerprinting** the backend database (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
4. **Extracting** sensitive data (databases, tables, columns, rows)

The tool was built from scratch to help students and security researchers understand how SQL injection works internally, without relying on complex tools like SQLMap.

---

## Features

- **SQL Injection Detection**
  - Error-based (including HTTP 500 detection)
  - Boolean-based blind
  - Time-based blind
  - UNION-based extraction

- **Database Fingerprinting**
  - Automatic identification of database type
  - Version, user, and database name extraction

- **Data Extraction**
  - Enumerate databases
  - Enumerate tables
  - Enumerate columns
  - Dump table data (row by row)

- **Session Management**
  - Automatic cookie handling (http.cookiejar)
  - Support for authenticated targets
  - Custom cookies via CLI

- **Cross-Platform**
  - Works on Kali Linux
  - Works on Windows

- **CLI Interface**
  - Subcommands: scan, detect, fingerprint, extract
  - Options: --help, --version, --config, --log-level, --cookie, --proxy

- **Output Management**
  - Save extracted data to text files
  - Automatic file naming with timestamps

---

## Project Structure

vectorinject/
├── vectorinject.py              # Main CLI entry point
├── README.md                    # This file
├── requirements.txt             # Dependencies (none - Pure Python)
├── LICENSE                      # MIT License
├── .gitignore                   # Git ignore file
│
├── core/                        # Core functionality
│   ├── __init__.py
│   ├── scanner.py               # URL & parameter scanner
│   ├── detector.py              # SQL injection detection engine
│   ├── fingerprint.py           # Database fingerprinting
│   └── extractor.py             # Data extraction engine
│
├── utils/                       # Utility modules
│   ├── __init__.py
│   ├── colors.py                # Terminal colors
│   ├── logger.py                # Logging utility
│   ├── http_client.py           # HTTP client with cookie jar
│   └── payloads.py              # SQL injection payloads
│
├── config/                      # Configuration
│   ├── __init__.py
│   └── settings.py              # Global settings
│
├── docs/                        # Documentation
│   └── Vector-Inject.pptx       # Presentation slides
│
├── output/                      # Extracted data (results)
│
├── payloads/                    # Payload wordlists
│
└── tests/                       # Unit tests

---

## Requirements

- **Python**: 3.8 or higher
- **Operating System**: Linux (Kali/Debian/Ubuntu) or Windows
- **Libraries**: Standard Library only (No Third-party)

The following Python Standard Library modules are used:

- socket, ssl, urllib.request, urllib.parse, http.cookiejar
- re, threading, queue, json, time, random
- hashlib, base64, argparse, logging, os, sys

---

## Installation

### On Kali Linux

git clone https://github.com/alwhababd447-dotcom/vectorinject.git
cd vectorinject
chmod +x vectorinject.py

### On Windows

git clone https://github.com/alwhababd447-dotcom/vectorinject.git
cd vectorinject
python vectorinject.py --help

---

## Usage

### Basic Help

python3 vectorinject.py --help

### Show Version

python3 vectorinject.py --version

### Scan a URL for Injection Points

python3 vectorinject.py scan --url "http://target.com/page.php?id=1"

### Detect SQL Injection

python3 vectorinject.py --cookie "PHPSESSID=xxx; security=low" detect --url "http://target.com/page.php?id=1"

### Extract Databases

python3 vectorinject.py --cookie "PHPSESSID=xxx" extract --url "http://target.com/page.php?id=1" --parameter id --dbs

### Extract Tables from a Database

python3 vectorinject.py --cookie "PHPSESSID=xxx" extract --url "http://target.com/page.php?id=1" --parameter id -D database_name --tables

### Extract Columns from a Table

python3 vectorinject.py --cookie "PHPSESSID=xxx" extract --url "http://target.com/page.php?id=1" --parameter id -D database_name -T table_name --columns

### Dump Table Data

python3 vectorinject.py --cookie "PHPSESSID=xxx" extract --url "http://target.com/page.php?id=1" --parameter id -D database_name -T table_name --dump

---

## CLI Options

| Option | Description |
|--------|-------------|
| --help, -h | Show help message |
| --version, -v | Show version |
| --config | Path to config file |
| --log-level | Logging level (DEBUG, INFO, WARNING, ERROR) |
| --threads | Number of threads (default: 10) |
| --timeout | Request timeout in seconds (default: 10) |
| --proxy | HTTP proxy |
| --user-agent | Custom User-Agent |
| --cookie | HTTP cookies |

---

## Subcommands

| Subcommand | Description |
|------------|-------------|
| scan | Scan URL for potential injection points |
| detect | Detect SQL injection vulnerability |
| fingerprint | Identify backend database |
| extract | Extract data from database |

---

## Live Demo - DVWA

We tested VectorInject against **DVWA (Damn Vulnerable Web Application)** on a local lab.

### Test Environment

| Component | Value |
|-----------|-------|
| Target | http://localhost/dvwa/vulnerabilities/sqli/ |
| Parameter | id |
| Security Level | Low |
| Database | MySQL |
| Detected Type | Error-based (HTTP 500) |

### Extracted Data

**Databases:**
- information_schema
- dvwa

**Tables (from dvwa):**
- guestbook
- users
- security_log
- access_log

**Columns (from users):**
- user_id, first_name, last_name, user, password, avatar, last_login, failed_login, role, account_enabled

**Extracted Users & Password Hashes (MD5):**

| User | Password Hash |
|------|---------------|
| admin | 5f4dcc3b5aa765d61d8327deb882cf99 |
| gordonb | e99a18c428cb38d5f260853678922e03 |
| 1337 | 8d3533d75ae2c3966d7e0d4fcc69216b |
| pablo | 0d107d09f5bbe40cade3de5c71e9e9b7 |
| smithy | 5f4dcc3b5aa765d61d8327deb882cf99 |

---

## Technical Details

### How It Works

1. **URL Parsing**: The tool parses the target URL and extracts all parameters
2. **Payload Injection**: Sends crafted SQL payloads in each parameter
3. **Response Analysis**: Analyzes the response (status code, length, content)
4. **Detection**:
   - Error-based: Detects SQL errors or HTTP 500 responses
   - Boolean-based: Compares responses between true/false conditions
   - Time-based: Measures response delay from SLEEP() payloads
   - UNION-based: Injects UNION SELECT to extract data directly
5. **Extraction**: Uses information_schema to enumerate databases, tables, and columns
6. **Dumping**: Extracts rows one by one using LIMIT and OFFSET

### Session Management

The tool uses Python's http.cookiejar to automatically:
- Save PHPSESSID from login responses
- Send cookies with every request
- Maintain authenticated sessions

---

## Legal Disclaimer

**This tool is intended for authorized penetration testing and educational purposes only.**

- DO NOT use this tool against systems you do not own or have explicit permission to test.
- Unauthorized access to computer systems is illegal and punishable by law.
- The author is not responsible for any misuse or damage caused by this tool.

By using VectorInject, you agree to use it responsibly and ethically.

---

## License

This project is licensed under the **MIT License** - see the LICENSE file for details.

---

## Acknowledgments

- Thanks to the open-source security community
- Inspired by tools like SQLMap, but built from scratch for educational purposes
- DVWA (Damn Vulnerable Web Application) for providing a safe testing environment

---

## Contact

- **Author**: Abdulwahab Nashwan Ajlan
- **Supervisor**: Dr. Ahmed Al-Suraihi
- **GitHub**: https://github.com/alwhababd447-dotcom/vectorinject

---

**If you find this project useful, please give it a star!**
