"""
VectorInject - Terminal Colors
"""

import sys
import os

# Check if terminal supports colors
if os.name == 'nt':
    os.system('color')

class Colors:
    """ANSI Color Codes"""
    
    # Reset
    RESET = '\033[0m'
    
    # Regular Colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bold
    BOLD = '\033[1m'
    BOLD_RED = '\033[1;31m'
    BOLD_GREEN = '\033[1;32m'
    BOLD_YELLOW = '\033[1;33m'
    BOLD_BLUE = '\033[1;34m'
    BOLD_MAGENTA = '\033[1;35m'
    BOLD_CYAN = '\033[1;36m'
    
    # Background
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'

def info(message):
    """Print info message in blue"""
    print(f"{Colors.BOLD_BLUE}[*]{Colors.RESET} {message}")

def success(message):
    """Print success message in green"""
    print(f"{Colors.BOLD_GREEN}[+]{Colors.RESET} {message}")

def warning(message):
    """Print warning message in yellow"""
    print(f"{Colors.BOLD_YELLOW}[!]{Colors.RESET} {message}")

def error(message):
    """Print error message in red"""
    print(f"{Colors.BOLD_RED}[-]{Colors.RESET} {message}")

def critical(message):
    """Print critical message in bold red with background"""
    print(f"{Colors.BG_RED}{Colors.WHITE}{Colors.BOLD}[CRITICAL]{Colors.RESET} {message}")

def banner():
    """Print VectorInject banner"""
    banner_text = f"""
{Colors.BOLD_RED}██╗   ██╗███████╗ ██████╗████████╗ ██████╗ ██████╗ 
{Colors.BOLD_RED}██║   ██║██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
{Colors.BOLD_RED}██║   ██║█████╗  ██║        ██║   ██║   ██║██████╔╝
{Colors.BOLD_RED}╚██╗ ██╔╝██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
{Colors.BOLD_RED} ╚████╔╝ ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
{Colors.BOLD_RED}  ╚═══╝  ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
{Colors.BOLD_CYAN}         SQL Injection + DB Extractor
{Colors.BOLD_YELLOW}              Version: 1.0.0
{Colors.BOLD_GREEN}         Author: Abdulwahab Nashwan Ajlan
{Colors.RESET}"""
    print(banner_text)

def separator():
    """Print a separator line"""
    print(f"{Colors.CYAN}{'=' * 60}{Colors.RESET}")

def section(title):
    """Print a section header"""
    print(f"\n{Colors.BOLD_CYAN}[ {title} ]{Colors.RESET}")
    print(f"{Colors.CYAN}{'-' * 60}{Colors.RESET}")

