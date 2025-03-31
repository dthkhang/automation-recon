import os, json, asyncio, logging, whois, aiofiles, subprocess
from datetime import datetime
from typing import List, Dict, Optional, Any
from .utils import prepare_url, run_command_async
from core.interfaces.scanner import ScannerInterface
from core.performance.optimizer import PerformanceOptimizer
from core.config.config import Config
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class WhoisScanner(ScannerInterface):
    """Retrieve WHOIS information for the target domain."""
    
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

    async def save_results(self, results: Dict[str, Any]) -> bool:
        """Save scan results to files."""
        try:
            # Save JSON output
            whois_info_path = os.path.join(self.output_dir, f"whois_info_{self.timestamp}.json")
            with open(whois_info_path, "w", encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            # Save human-readable output
            whois_info_txt_path = os.path.join(self.output_dir, f"whois_info_{self.timestamp}.txt")
            with open(whois_info_txt_path, "w", encoding='utf-8') as f:
                f.write(f"WHOIS Information for {results['domain']}\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Scan Time: {results['timestamp']}\n\n")
                f.write("Raw WHOIS Data:\n")
                f.write("-" * 30 + "\n")
                for line in results['raw_data']:
                    f.write(f"{line}\n")
            
            logger.info("\033[92m[+] Results saved successfully\033[0m")
            return True
            
        except Exception as e:
            logger.error(f"\033[91m[!] Error saving results: {str(e)}\033[0m")
            return False
    
    async def get_whois_info(self) -> Dict[str, Any]:
        """Get WHOIS information for the domain."""
        try:
            logger.info("\033[92m[+] Starting WHOIS lookup...\033[0m")
            
            # Initialize performance optimizer
            await self.optimizer.initialize()
            
            # Run whois command
            logger.info("\033[92m[+] Running whois command...\033[0m")
            whois_cmd = f"whois {self.domain}"
            whois_result = await self.optimizer.run_command_async(whois_cmd)
            
            # Process WHOIS data
            whois_data = {
                'timestamp': datetime.now(),
                'domain': self.domain,
                'raw_data': whois_result,
                'parsed_data': self._parse_whois_data(whois_result)
            }
            
            # Save results
            await self.save_results(whois_data)
            
            logger.info("\033[92m[+] WHOIS lookup completed\033[0m")
            return whois_data
            
        except Exception as e:
            logger.error(f"\033[91m[!] Error getting WHOIS information: {str(e)}\033[0m")
            return {}
        finally:
            await self.optimizer.cleanup()
    
    async def scan(self) -> Dict[str, Any]:
        """Run the complete WHOIS scanning process."""
        try:
            logger.info("\033[92m[+] Starting WHOIS scanning...\033[0m")
            
            # Format URL using Config
            formatted_domain = self.config.format_url(self.domain)
            domain = urlparse(formatted_domain).netloc
            
            # Run whois
            logger.info("\033[92m[+] Running whois...\033[0m")
            whois_cmd = f"whois {domain}"
            whois_result = subprocess.run(whois_cmd, shell=True, capture_output=True, text=True)
            
            if whois_result.returncode != 0:
                logger.error(f"\033[91m[!] Error running whois: {whois_result.stderr}\033[0m")
                return {}
                
            # Process results
            raw_data = whois_result.stdout.splitlines()
            whois_info = {
                "domain": domain,
                "raw_data": raw_data,
                "timestamp": datetime.now().isoformat()
            }
            
            # Save results
            await self.save_results(whois_info)
            logger.info(f"\033[92m[+] Results saved to {self.output_dir}/\033[0m")
            
            return whois_info
            
        except Exception as e:
            logger.error(f"\033[91m[!] Error during WHOIS scanning: {str(e)}\033[0m")
            return {}
    
    def _parse_whois_data(self, raw_data: List[str]) -> Dict[str, Any]:
        """Parse raw WHOIS data into structured format."""
        parsed = {
            'registrar': {},
            'dates': {},
            'nameservers': [],
            'status': [],
            'emails': [],
            'dnssec': False
        }
        
        for line in raw_data:
            line = line.strip()
            if not line or line.startswith('>>>'):
                continue
                
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if 'registrar' in key:
                    parsed['registrar'][key] = value
                elif any(date in key for date in ['created', 'updated', 'expired']):
                    try:
                        parsed['dates'][key] = datetime.strptime(value, '%Y-%m-%d')
                    except:
                        parsed['dates'][key] = value
                elif 'nameserver' in key:
                    parsed['nameservers'].append(value)
                elif 'status' in key:
                    parsed['status'].append(value)
                elif '@' in value:
                    parsed['emails'].append(value)
                elif 'dnssec' in key:
                    parsed['dnssec'] = 'signed' in value.lower()
        
        return parsed 