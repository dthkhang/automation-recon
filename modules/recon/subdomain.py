import os, json, asyncio, aiohttp, logging, aiofiles, subprocess
from datetime import datetime
from typing import List, Dict, Optional, Any
from .utils import RateLimiter, prepare_url, run_command_async, TIMEOUT
from core.config.config import Config
from core.interfaces.scanner import ScannerInterface
from core.performance.optimizer import PerformanceOptimizer

logger = logging.getLogger(__name__)

class SubdomainScanner(ScannerInterface):
    """Find subdomains of the target domain."""
    
    def __init__(self, domain: str, output_dir: str):
        super().__init__(domain, output_dir)
        self.rate_limiter = RateLimiter(10)
        self.semaphore = asyncio.Semaphore(2)  # Limit concurrent processes to 2
        self.optimizer = PerformanceOptimizer()
        self.config = Config()
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.subdomains: List[Dict] = []
        self.json_file_path = None  # Thêm biến để lưu đường dẫn file JSON
        
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

    async def save_results(self, subdomains: List[Dict[str, Any]]) -> bool:
        """Save scan results to files."""
        try:
            # Save JSON output with only subdomains
            self.json_file_path = os.path.join(self.output_dir, f"subdomain_info_{self.timestamp}.json")
            with open(self.json_file_path, "w", encoding='utf-8') as f:
                json.dump(subdomains, f, indent=2, ensure_ascii=False)
                
            # Save human-readable output
            txt_file = os.path.join(self.output_dir, f"subdomain_info_{self.timestamp}.txt")
            with open(txt_file, "w", encoding='utf-8') as f:
                f.write("Subdomain Scanning Results\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Domain: {self.domain}\n")
                f.write(f"Total Subdomains: {len(subdomains)}\n")
                f.write(f"Scan Time: {datetime.now().isoformat()}\n\n")
                
                for subdomain in subdomains:
                    f.write(f"{subdomain['subdomain']}\n")
                    
            logger.info("\033[92m[+] Results saved successfully\033[0m")
            return True
            
        except Exception as e:
            logger.error(f"\033[91m[!] Error saving results: {str(e)}\033[0m")
            return False

    async def find_subdomains(self) -> List[Dict[str, Any]]:
        """Find subdomains using multiple tools."""
        try:
            logger.info("\033[92m[+] Starting subdomain enumeration...\033[0m")
            
            # Initialize performance optimizer
            await self.optimizer.initialize()
            
            # Run subfinder
            logger.info("\033[92m[+] Running subfinder...\033[0m")
            subfinder_cmd = f"subfinder -d {self.domain} -silent"
            subfinder_result = await self.optimizer.run_command_async(subfinder_cmd)
            
            # Process subfinder results
            subdomains = [line.strip() for line in subfinder_result if line.strip()]
            
            if subdomains:
                logger.info(f"\033[91m[+] Found {len(subdomains)} subdomains. Checking alive ones...\033[0m")
            else:
                logger.info("\033[93m[!] No subdomains found\033[0m")
            
            # Check which subdomains are alive using httpx
            if subdomains:
                logger.info("\033[92m[+] Checking subdomain availability...\033[0m")
                alive_subdomains = await self.check_alive_subdomains(subdomains)
                
                # Save results
                await self.save_results(alive_subdomains)
                
                # Check for subdomain takeover
                await self._check_subdomain_takeover()
                
                # Check for DNS zone transfer
                await self._check_dns_zone_transfer()
                
                # Check CT logs
                await self._check_ct_logs()
                
                return alive_subdomains
            
            logger.info("\033[92m[+] Subdomain enumeration completed\033[0m")
            return []
            
        except Exception as e:
            logger.error(f"\033[91m[!] Error during subdomain enumeration: {str(e)}\033[0m")
            return []
        finally:
            await self.optimizer.cleanup()

    async def scan(self) -> List[Dict[str, Any]]:
        """Implement the scan method from ScannerInterface."""
        if not await self.validate_input():
            return []
        return await self.find_subdomains()

    async def check_alive_subdomains(self, subdomains: List[str]) -> List[Dict[str, Any]]:
        """Check which subdomains are alive using httpx."""
        try:
            logger.info("\033[92m[+] Checking subdomain availability...\033[0m")
            
            # Format domain using Config
            formatted_domain = self.config.format_url(self.domain)
            
            # Run subfinder to get subdomains
            subfinder_cmd = f"subfinder -d {formatted_domain} -silent"
            subfinder_result = subprocess.run(subfinder_cmd, shell=True, capture_output=True, text=True)
            
            if subfinder_result.returncode != 0:
                logger.error(f"\033[91m[!] Command failed: {subfinder_cmd}\033[0m")
                logger.error(f"\033[91m[!] Error: {subfinder_result.stderr}\033[0m")
                return []
                
            # Process results
            alive_subdomains = []
            for line in subfinder_result.stdout.splitlines():
                if line.strip():
                    alive_subdomains.append({
                        "subdomain": line.strip(),
                        "timestamp": datetime.now().isoformat()
                    })
                        
            if not alive_subdomains:
                logger.info("\033[93m[!] No subdomains found\033[0m")
            else:
                logger.info(f"\033[91m[+] Found {len(alive_subdomains)} subdomains\033[0m")
                
            return alive_subdomains
            
        except Exception as e:
            logger.error(f"\033[91m[!] Error checking subdomains: {str(e)}\033[0m")
            return []

    async def _check_subdomain_takeover(self):
        logger.info("\033[92m[+] Checking for subdomain takeover vulnerabilities...\033[0m")
        try:
            # Chạy subfinder để lấy danh sách subdomains
            subfinder_cmd = f"subfinder -d {self.domain} -silent"
            subfinder_result = await run_command_async(subfinder_cmd, self.semaphore, self.output_dir)
            
            if not subfinder_result:
                logger.warning("\033[93m[!] No subdomains found\033[0m")
                return
                
            # Lưu kết quả subfinder vào file txt
            txt_file = os.path.join(self.output_dir, f"subdomain_takeover_{self.timestamp}.txt")
            with open(txt_file, "w") as f:
                f.write("\n".join(subfinder_result))
                
            # Chạy subjack để kiểm tra takeover
            subjack_cmd = f"subjack -w {txt_file} -t 100 -timeout 30"
            subjack_result = await run_command_async(subjack_cmd, self.semaphore, self.output_dir)
            
            if subjack_result:
                # Lưu kết quả subjack vào file JSON
                json_file = os.path.join(self.output_dir, f"subdomain_takeover_{self.timestamp}.json")
                with open(json_file, "w") as f:
                    json.dump({
                        "timestamp": self.timestamp,
                        "domain": self.domain,
                        "vulnerable_subdomains": subjack_result
                    }, f, indent=2)
                logger.info("\033[91m[+] Found potential subdomain takeover vulnerabilities\033[0m")
            else:
                logger.info("\033[92m[+] No subdomain takeover vulnerabilities found\033[0m")
                
        except Exception as e:
            logger.error(f"\033[91m[!] Error checking subdomain takeover: {str(e)}\033[0m")

    async def _check_dns_zone_transfer(self):
        logger.info("\033[92m[+] Checking for DNS zone transfer vulnerability...\033[0m")
        try:
            # Chạy dig để kiểm tra zone transfer
            dig_cmd = f"dig axfr {self.domain}"
            dig_result = await run_command_async(dig_cmd, self.semaphore, self.output_dir)
            
            if dig_result and "Transfer failed" not in dig_result[0]:
                # Lưu kết quả vào file txt
                txt_file = os.path.join(self.output_dir, f"dns_zone_transfer_{self.timestamp}.txt")
                with open(txt_file, "w") as f:
                    f.write("\n".join(dig_result))
                    
                # Lưu kết quả vào file JSON
                json_file = os.path.join(self.output_dir, f"dns_zone_transfer_{self.timestamp}.json")
                with open(json_file, "w") as f:
                    json.dump({
                        "timestamp": self.timestamp,
                        "domain": self.domain,
                        "vulnerable": True,
                        "records": dig_result
                    }, f, indent=2)
                logger.warning("\033[93m[!] Potential DNS zone transfer vulnerability found\033[0m")
            else:
                logger.info("\033[92m[+] No DNS zone transfer vulnerability found\033[0m")
                
        except Exception as e:
            logger.error(f"\033[91m[!] Error checking DNS zone transfer: {str(e)}\033[0m")

    async def _check_ct_logs(self):
        logger.info("\033[92m[+] Checking Certificate Transparency logs...\033[0m")
        try:
            results = await run_command_async(f"ct-subdomain-finder {self.domain}", self.semaphore, self.output_dir)
            if results:
                async with aiofiles.open(os.path.join(self.output_dir, "ct_logs.txt"), "w") as f:
                    await f.write("\n".join(results))
                logger.info("\033[91m[+] Found subdomains from CT logs\033[0m")
        except Exception as e:
            logger.error(f"\033[91m[!] Error checking CT logs: {str(e)}\033[0m") 