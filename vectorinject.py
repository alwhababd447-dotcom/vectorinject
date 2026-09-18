#!/usr/bin/env python3
"""
VectorInject - SQL Injection + DB Extractor
Main CLI Entry Point
Author: Abdulwahab Nashwan Ajlan
Version: 1.0.0
"""

import sys
import os
import argparse
import time

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from utils import colors, logger
from config import settings


def cmd_scan(args):
    from core.scanner import Scanner
    colors.banner()
    colors.section("Scan Mode")
    colors.info(f"Target URL: {args.url}")
    scanner = Scanner(args.url)
    result = scanner.scan()
    return result


def cmd_detect(args):
    from core.scanner import Scanner
    from core.detector import Detector
    from utils.http_client import HTTPClient
    from utils import colors
    
    colors.banner()
    colors.section("Detect Mode")
    colors.info(f"Target URL: {args.url}")
    
    # Parse cookies
    cookies = {}
    if args.cookie:
        for item in args.cookie.split(';'):
            if '=' in item:
                k, v = item.strip().split('=', 1)
                cookies[k] = v
        colors.info(f"Using {len(cookies)} cookie(s)")
    
    # Create client
    client = HTTPClient(cookies=cookies)
    
    # Find injection points
    scanner = Scanner(args.url, client=client)
    scanner.parse_url()
    points = scanner.get_injection_points()
    
    if not points:
        colors.error("No parameters found in URL")
        return
    
    # Test each parameter
    vulnerable_params = []
    for point in points:
        param = point['parameter']
        if param.lower() == 'submit':
            continue  # Skip submit button
        
        colors.info(f"Testing parameter: {param}")
        
        detector = Detector(args.url, param, client=client)
        result = detector.detect()
        
        if result['vulnerable']:
            colors.success(f"VULNERABLE: {param}")
            colors.info(f"Type: {result['type']}")
            if result.get('database'):
                colors.info(f"Database: {result['database']}")
            vulnerable_params.append({
                'parameter': param,
                'type': result['type'],
                'evidence': result['evidence']
            })
        else:
            colors.warning(f"Not vulnerable: {param}")
    
    # Summary
    colors.section("Summary")
    if vulnerable_params:
        colors.success(f"Found {len(vulnerable_params)} vulnerable parameter(s)")
        for vp in vulnerable_params:
            print(f"  - {vp['parameter']}: {vp['type']}")
    else:
        colors.warning("No vulnerable parameters found")

def cmd_fingerprint(args):
    from core.scanner import Scanner
    from core.fingerprint import Fingerprint
    colors.banner()
    colors.section("Fingerprint Mode")
    colors.info(f"Target URL: {args.url}")
    scanner = Scanner(args.url)
    scanner.parse_url()
    points = scanner.get_injection_points()
    if not points:
        colors.error("No parameters found in URL")
        return
    for point in points:
        param = point['parameter']
        fp = Fingerprint(args.url, param)
        result = fp.fingerprint()
        if result['database']:
            colors.success(f"Fingerprint complete for: {param}")


def cmd_extract(args):
    from core.extractor import Extractor
    from utils.http_client import HTTPClient
    from utils import colors
    import time
    
    colors.banner()
    colors.section("Extract Mode")
    colors.info(f"Target URL: {args.url}")
    colors.info(f"Parameter: {args.parameter}")
    
    # Parse cookies
    cookies = {}
    if args.cookie:
        for item in args.cookie.split(';'):
            if '=' in item:
                k, v = item.strip().split('=', 1)
                cookies[k] = v
        colors.info(f"Using {len(cookies)} cookie(s)")
    
    # Create client
    client = HTTPClient(cookies=cookies)
    
    # Determine database type
    db_type = args.db_type or "MySQL"
    colors.info(f"Database type: {db_type}")
    print()
    
    ext = Extractor(args.url, args.parameter, db_type, client=client)
    
    # Step 1: Extract databases
    if args.dbs:
        databases = ext.extract_databases()
        if not databases:
            colors.error("Failed to extract databases")
            return
    
    # Step 2: Extract tables
    if args.database and args.tables:
        tables = ext.extract_tables(args.database)
        if not tables:
            colors.error("Failed to extract tables")
            return
    
    # Step 3: Extract columns
    if args.database and args.table and args.columns:
        columns = ext.extract_columns(args.database, args.table)
        if not columns:
            colors.error("Failed to extract columns")
            return
    
    # Step 4: Dump data
    if args.database and args.table and args.dump:
        data = ext.dump_table(args.database, args.table)
        
        # Save results
        if data:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"dump_{args.database}_{args.table}_{timestamp}.txt"
            import os
            from config import settings
            filepath = os.path.join(settings.OUTPUT_DIR, filename)
            
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(f"VectorInject - Data Dump\n")
                    f.write(f"Target: {args.url}\n")
                    f.write(f"Database: {args.database}\n")
                    f.write(f"Table: {args.table}\n")
                    f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 60 + "\n\n")
                    for entry in data:
                        for k, v in entry.items():
                            f.write(f"{k}: {v}\n")
                        f.write("-" * 40 + "\n")
                
                colors.success(f"Saved to: {filepath}")
            except Exception as e:
                colors.error(f"Failed to save: {e}")

def print_help():
    colors.banner()
    help_text = """
USAGE:
    vectorinject.py <command> [options]

COMMANDS:
    scan          Scan URL for potential injection points
    detect        Detect SQL injection vulnerability
    fingerprint   Identify backend database
    extract       Extract data from database
    help          Show this help message

EXAMPLES:
    python3 vectorinject.py scan --url "http://target.com/page.php?id=1"
    python3 vectorinject.py detect --url "http://target.com/page.php?id=1"
    python3 vectorinject.py fingerprint --url "http://target.com/page.php?id=1"
    python3 vectorinject.py extract --url "http://target.com/page.php?id=1" --parameter id --dbs
    python3 vectorinject.py extract --url "http://target.com/page.php?id=1" --parameter id -D db -T users --dump

GLOBAL OPTIONS:
    --help, -h          Show this help
    --version, -v       Show version
    --log-level         Log level (DEBUG, INFO, WARNING, ERROR)

LEGAL DISCLAIMER:
    This tool is for authorized penetration testing only.
"""
    print(help_text)


def main():
    parser = argparse.ArgumentParser(
        description="VectorInject - SQL Injection + DB Extractor",
        add_help=False
    )
    parser.add_argument("--help", "-h", action="store_true")
    parser.add_argument("--version", "-v", action="store_true")
    parser.add_argument("--config", default="config/settings.py")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--proxy", default=None)
    parser.add_argument("--user-agent", default=None)
    parser.add_argument("--cookie", default=None)

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("--url", required=True)

    detect_parser = subparsers.add_parser("detect")
    detect_parser.add_argument("--url", required=True)

    fp_parser = subparsers.add_parser("fingerprint")
    fp_parser.add_argument("--url", required=True)

    ext_parser = subparsers.add_parser("extract")
    ext_parser.add_argument("--url", required=True)
    ext_parser.add_argument("--parameter", required=True)
    ext_parser.add_argument("--db-type", default="MySQL")
    ext_parser.add_argument("--dbs", action="store_true")
    ext_parser.add_argument("-D", "--database")
    ext_parser.add_argument("--tables", action="store_true")
    ext_parser.add_argument("-T", "--table")
    ext_parser.add_argument("--columns", action="store_true")
    ext_parser.add_argument("--dump", action="store_true")

    args = parser.parse_args()

    if args.version:
        print(f"VectorInject v{settings.VERSION}")
        print(f"Author: {settings.AUTHOR}")
        sys.exit(0)

    if args.help or not args.command:
        print_help()
        sys.exit(0)

    logger.setup_logger(level=args.log_level)

    try:
        if args.command == "scan":
            cmd_scan(args)
        elif args.command == "detect":
            cmd_detect(args)
        elif args.command == "fingerprint":
            cmd_fingerprint(args)
        elif args.command == "extract":
            cmd_extract(args)
        else:
            print_help()
    except KeyboardInterrupt:
        print("\n")
        colors.warning("Interrupted by user")
        sys.exit(0)
    except Exception as e:
        colors.error(f"Error: {str(e)}")
        if args.log_level == "DEBUG":
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
