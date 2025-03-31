#!/usr/bin/env python3
import argparse, asyncio, os, sys
from datetime import datetime
from typing import Optional, List, Dict, Any
from core.config.config import Config
from core.interfaces.scanner import ScannerInterface
from modules.recon.subdomain import SubdomainScanner
from modules.recon.technology import TechnologyScanner
from modules.recon.directory import DirectoryScanner
from modules.recon.dns import DNSScanner
from modules.recon.whois import WhoisScanner
from modules.recon.url import URLScanner

def parse_args():
    parser = argparse.ArgumentParser(
        description='AI-Powered Penetration Testing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py -u example.com
  python3 main.py -u https://example.com
        """
    )
    parser.add_argument('-u', '--url', required=True, help='Target domain or URL to scan')
    return parser.parse_args()

async def run_scanner(scanner: ScannerInterface) -> Dict[str, Any]:
    """Run a single scanner and return its results."""
    try:
        await scanner.start()
        results = await scanner.scan()
        await scanner.end()
        return results
    except Exception as e:
        print(f"Error running {scanner.__class__.__name__}: {str(e)}")
        return {}

async def scan(domain: str, output_dir: str):
    """Run all scanners."""
    try:
        # Initialize scanners
        subdomain_scanner = SubdomainScanner(domain, output_dir)
        tech_scanner = TechnologyScanner(domain, output_dir)
        dir_scanner = DirectoryScanner(domain, output_dir)
        dns_scanner = DNSScanner(domain, output_dir)
        whois_scanner = WhoisScanner(domain, output_dir)
        url_scanner = URLScanner(domain, output_dir)

        # First run subdomain scanner
        print("\n[+] Running subdomain enumeration...")
        subdomain_results = await subdomain_scanner.scan()

        # Then run URL scanner (which will now include subdomains)
        print("\n[+] Running URL enumeration...")
        url_results = await url_scanner.scan()

        # Run remaining scanners concurrently
        print("\n[+] Running remaining scanners...")
        await asyncio.gather(
            tech_scanner.scan(),
            dir_scanner.scan(),
            dns_scanner.scan(),
            whois_scanner.scan()
        )

        print(f"\nScan completed successfully!")
        print(f"Results saved to: {output_dir}")
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error during scan: {str(e)}")
        sys.exit(1)

async def main():
    try:
        args = parse_args()
        
        # Ensure required directories exist
        Config.ensure_directories()
        
        # Get scan directory for this target
        scan_dir = Config.get_scan_dir(args.url)
        print(f"Scan results will be saved to: {scan_dir}")
        
        await scan(args.url, scan_dir)
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error during scan: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())