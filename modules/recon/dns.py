import os, json, asyncio, aiofiles, subprocess
import logging, dns.resolver
from datetime import datetime
from typing import List, Dict, Optional, Any
from .utils import prepare_url, run_command_async
from core.interfaces.scanner import ScannerInterface
from core.performance.optimizer import PerformanceOptimizer
from core.config.config import Config
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class DNSScanner(ScannerInterface):
    def __init__(self, domain: str, output_dir: str):
        super().__init__(domain, output_dir)
        self.semaphore = asyncio.Semaphore(2)  # Limit concurrent processes to 2
        self.optimizer = PerformanceOptimizer()
        self.config = Config()
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)

    async def validate_input(self) -> bool:
        """Validate input parameters."""
        try:
            if not self.domain:
                logger.error("\033[91m[!] Domain is required\033[0m")
                return False
            if not self.output_dir:
                logger.error("\033[91m[!] Output directory is required\033[0m")
                return False
            return True
        except Exception as e:
            logger.error(f"\033[91m[!] Error validating input: {str(e)}\033[0m")
            return False

    async def save_results(self, results: List[Dict[str, Any]]) -> bool:
        """Save scan results to files."""
        try:
            # Prepare results dictionary
            results_dict = {
                'timestamp': datetime.now().isoformat(),
                'domain': self.domain,
                'total_records': len(results),
                'records': results
            }
            
            # Save JSON output
            json_file = os.path.join(self.output_dir, f"dns_info_{self.timestamp}.json")
            with open(json_file, "w", encoding='utf-8') as f:
                json.dump(results_dict, f, indent=2, ensure_ascii=False)
                
            # Save human-readable output
            txt_file = os.path.join(self.output_dir, f"dns_info_{self.timestamp}.txt")
            with open(txt_file, "w", encoding='utf-8') as f:
                f.write("DNS Scanning Results\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Domain: {self.domain}\n")
                f.write(f"Total Records: {len(results)}\n")
                f.write(f"Scan Time: {datetime.now().isoformat()}\n\n")
                
                for record in results:
                    f.write(f"Type: {record['type']}\n")
                    f.write(f"Records:\n{record['records']}\n")
                    f.write("-" * 50 + "\n\n")
                    
            logger.info("\033[92m[+] Results saved successfully\033[0m")
            return True
            
        except Exception as e:
            logger.error(f"\033[91m[!] Error saving results: {str(e)}\033[0m")
            return False

    async def get_dns_info(self) -> Dict[str, Any]:
        """Get comprehensive DNS information."""
        logger.info(f"\033[92m[+] Getting comprehensive DNS information for {self.domain}...\033[0m")
        
        try:
            dns_info = {
                'timestamp': datetime.now(),
                'domain': self.domain,
                'records': {},
                'misconfigurations': []
            }
            
            # Get all common DNS record types
            record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT', 'SRV']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(self.domain, record_type)
                    dns_info['records'][record_type] = [str(rdata) for rdata in answers]
                except dns.resolver.NoAnswer:
                    dns_info['records'][record_type] = []
                except Exception as e:
                    logger.error(f"\033[91m[!] Error getting {record_type} records: {str(e)}\033[0m")
                    dns_info['records'][record_type] = []
            
            # Check for DNS misconfigurations
            await self._check_dns_misconfigurations(dns_info)
            
            # Save results
            await self.save_results(dns_info['records'])
            
            return dns_info
            
        except Exception as e:
            logger.error(f"\033[91m[!] Error getting DNS information: {str(e)}\033[0m")
            return {}

    async def scan(self) -> Dict[str, Any]:
        """Run the complete DNS scanning process."""
        try:
            logger.info("\033[92m[*] Starting DNS scanning...\033[0m")
            
            # Format URL using Config
            formatted_domain = self.config.format_url(self.domain)
            domain = urlparse(formatted_domain).netloc
            
            # Run dig for different record types
            logger.info("\033[92m[*] Running dig...\033[0m")
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
            dns_records = {}
            
            for record_type in record_types:
                dig_cmd = f"dig {domain} {record_type}"
                dig_result = subprocess.run(dig_cmd, shell=True, capture_output=True, text=True)
                
                if dig_result.returncode == 0:
                    dns_records[record_type] = dig_result.stdout.strip()
            
            # Process results
            dns_info = []
            for record_type, output in dns_records.items():
                dns_info.append({
                    "type": record_type,
                    "records": output,
                    "timestamp": datetime.now().isoformat()
                })
                        
            if dns_info:
                logger.info(f"\033[91m[+] Found {len(dns_info)} DNS records\033[0m")
            else:
                logger.info("\033[93m[!] No DNS records found\033[0m")
                        
            # Save results
            await self.save_results(dns_info)
            logger.info(f"\033[92m[+] Results saved to {self.output_dir}/\033[0m")
            
            return dns_info
            
        except Exception as e:
            logger.error(f"\033[91m[!] Error during DNS scanning: {str(e)}\033[0m")
            return {}

    async def _check_dns_misconfigurations(self, dns_info: Dict[str, Any]):
        """Check for DNS misconfigurations."""
        logger.info("\033[92m[+] Checking for DNS misconfigurations...\033[0m")
        try:
            # Check for DNS recursion
            results = await run_command_async(f"dig +recurse {self.domain}", self.semaphore, self.output_dir)
            if "Recursion requested" in results[0]:
                issue = "DNS recursion is enabled - potential security risk"
                logger.warning(f"\033[93m[!] {issue}\033[0m")
                dns_info['misconfigurations'].append(issue)
            
            # Check for DNSSEC
            results = await run_command_async(f"dig +dnssec {self.domain}", self.semaphore, self.output_dir)
            if "RRSIG" in results[0]:
                logger.info("\033[92m[+] DNSSEC is enabled\033[0m")
            else:
                issue = "DNSSEC is not enabled - consider implementing DNSSEC"
                logger.warning(f"\033[93m[!] {issue}\033[0m")
                dns_info['misconfigurations'].append(issue)
            
        except Exception as e:
            logger.error(f"\033[91m[!] Error checking DNS misconfigurations: {str(e)}\033[0m") 