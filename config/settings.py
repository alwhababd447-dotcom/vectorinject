"""
VectorInject - Global Settings
Author: Abdulwahab Nashwan Ajlan
Project: SQL Injection + DB Extractor
"""

import os

# ============================================================
# Project Information
# ============================================================

PROJECT_NAME = "VectorInject"
VERSION = "1.0.0"
AUTHOR = "Abdulwahab Nashwan Ajlan"
DESCRIPTION = "SQL Injection + DB Extractor"

# ============================================================
# Paths
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAYLOAD_DIR = os.path.join(BASE_DIR, "payloads")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
LOG_DIR = os.path.join(BASE_DIR, "logs")

# Create directories if not exist
for directory in [PAYLOAD_DIR, OUTPUT_DIR, LOG_DIR]:
    if not os.path.exists(directory):
        os.makedirs(directory)

# ============================================================
# HTTP Settings
# ============================================================

DEFAULT_TIMEOUT = 10
DEFAULT_THREADS = 10
DEFAULT_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
DEFAULT_PROXY = None
DEFAULT_COOKIES = {}

# SSL Verification
VERIFY_SSL = False

# Follow Redirects
FOLLOW_REDIRECTS = True
MAX_REDIRECTS = 5

# ============================================================
# SQL Injection Settings
# ============================================================

# Error-based detection
ERROR_PATTERNS = [
    "SQL syntax",
    "mysql_fetch",
    "mysqli",
    "You have an error in your SQL syntax",
    "Warning: mysql",
    "unclosed quotation mark",
    "Microsoft OLE DB Provider for ODBC Drivers",
    "Microsoft OLE DB Provider for SQL Server",
    "Incorrect syntax near",
    "PostgreSQL",
    "pg_query",
    "psql",
    "ORA-01756",
    "Oracle error",
    "SQLite",
    "SQLite3::query",
    "sqlite3.OperationalError",
    "Syntax error in query",
    "Unclosed quotation mark",
    "quoted string not properly terminated",
]

# Boolean-based detection
BOOLEAN_TRUE_PAYLOAD = "' AND '1'='1"
BOOLEAN_FALSE_PAYLOAD = "' AND '1'='2"

# Time-based detection
TIME_BASED_PAYLOAD = "' AND SLEEP(5)-- -"
TIME_BASED_DELAY = 5
TIME_BASED_THRESHOLD = 4

# ============================================================
# Database Fingerprinting
# ============================================================

DATABASE_SIGNATURES = {
    "MySQL": ["mysql", "mysqli", "mariadb"],
    "PostgreSQL": ["postgresql", "pgsql", "psql"],
    "MSSQL": ["mssql", "microsoft sql server", "oledb"],
    "Oracle": ["oracle", "ora-"],
    "SQLite": ["sqlite", "sqlite3"],
}

# ============================================================
# Extraction Settings
# ============================================================

MAX_DATABASES = 50
MAX_TABLES = 200
MAX_COLUMNS = 100
MAX_ROWS = 1000

# ============================================================
# Logging Settings
# ============================================================

LOG_LEVEL = "INFO"
LOG_FORMAT = "[%(asctime)s] [%(levelname)s] %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
LOG_FILE = os.path.join(LOG_DIR, "vectorinject.log")

# ============================================================
# Output Settings
# ============================================================

OUTPUT_FORMAT = "txt"  # txt, json, csv
SAVE_RESULTS = True
