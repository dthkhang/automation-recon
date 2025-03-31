import asyncio, aiofiles, aiohttp, json, os, logging, subprocess, re
from datetime import datetime
from typing import List, Dict, Optional, Any
from .utils import prepare_url, run_command_async, TIMEOUT, RateLimiter
from core.config.config import Config
from core.interfaces.scanner import ScannerInterface

logger = logging.getLogger(__name__)

class DirectoryScanner(ScannerInterface):
    """Find directories and files on the target."""
    
    def __init__(self, domain: str, output_dir: str):
        super().__init__(domain, output_dir)
        self.semaphore = asyncio.Semaphore(2)  # Limit concurrent ffuf processes to 2
        self.config = Config()
        self.wordlist = self.config.get_wordlist('directory')
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)

    def convert_txt_to_json(self, txt_file: str, json_key: str = "Directory") -> List[Dict[str, Any]]:
        """Convert txt file to JSON format."""
        try:
            with open(txt_file, 'r') as file:
                content = file.read()
                # Regex pattern để parse kết quả từ ffuf
                pattern = r'\[2K\[Status: (\d+), Size: (\d+), Words: (\d+), Lines: (\d+), Duration: (\d+)ms\].*?\[2K\| URL \| (http:\/\/[^\n]+)'
                matches = re.finditer(pattern, content, re.DOTALL)

                results = []
                for match in matches:
                    status_code = match.group(1)
                    size = match.group(2)
                    words = match.group(3)
                    lines = match.group(4)
                    duration = match.group(5)
                    url = match.group(6)

                    results.append({
                        "URL": url.strip(),
                        "Status Code": int(status_code),
                        "Size": int(size),
                        "Words": int(words),
                        "Lines": int(lines),
                        "Duration": int(duration)
                    })

                # Tạo và lưu file JSON
                json_file = os.path.splitext(txt_file)[0] + ".json"
                json_data = {
                    json_key: results,
                    "timestamp": datetime.now().isoformat(),
                    "domain": self.domain,
                    f"total_{json_key.lower()}": len(results)
                }

                with open(json_file, 'w') as f:
                    json.dump(json_data, f, indent=4)

                logger.info(f"\033[92m[+] Converted to JSON: {json_file}\033[0m")
                logger.info(f"\033[92m[+] Found {len(results)} {json_key.lower()}\033[0m")
                return results

        except Exception as e:
            logger.error(f"\033[91m[!] Error converting to JSON: {str(e)}\033[0m")
            return []

    async def validate_input(self) -> bool:
        """Validate input parameters."""
        try:
            if not self.domain:
                logger.error("\033[91m[!] Domain is required\033[0m")
                return False
            if not self.output_dir:
                logger.error("\033[91m[!] Output directory is required\033[0m")
                return False
            if not os.path.exists(self.wordlist):
                logger.error(f"\033[91m[!] Wordlist not found: {self.wordlist}\033[0m")
                return False
            return True
        except Exception as e:
            logger.error(f"\033[91m[!] Error validating input: {str(e)}\033[0m")
            return False

    async def save_results(self, results: List[Dict[str, Any]]) -> bool:
        """Save scan results to files."""
        try:
            # Prepare results dictionary with serializable datetime
            results_dict = {
                'timestamp': datetime.now().isoformat(),
                'domain': self.domain,
                'total_directories': len(results),
                'directories': results
            }
            
            # Save JSON output
            json_file = os.path.join(self.output_dir, f"directory_info_{self.timestamp}.json")
            with open(json_file, "w", encoding='utf-8') as f:
                json.dump(results_dict, f, indent=2, ensure_ascii=False)
                
            # Save human-readable output
            txt_file = os.path.join(self.output_dir, f"directory_info_{self.timestamp}.txt")
            with open(txt_file, "w", encoding='utf-8') as f:
                f.write("Directory Scanning Results\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Domain: {self.domain}\n")
                f.write(f"Total Directories: {len(results)}\n")
                f.write(f"Scan Time: {datetime.now().isoformat()}\n\n")
                
                for dir_info in results:
                    f.write(f"URL: {dir_info['url']}\n")
                    f.write(f"Status Code: {dir_info.get('status_code', 'N/A')}\n")
                    f.write(f"Content Length: {dir_info.get('content_length', 'N/A')}\n")
                    f.write("-" * 50 + "\n\n")
                    
            logger.info("\033[92m[+] Results saved successfully\033[0m")
            return True
            
        except Exception as e:
            logger.error(f"\033[91m[!] Error saving results: {str(e)}\033[0m")
            return False
    
    async def scan(self) -> List[Dict[str, Any]]:
        """Run the complete directory scanning process."""
        try:
            logger.info("\033[92m[+] Starting directory scanning...\033[0m")
            
            # Format URL using Config
            formatted_domain = self.config.format_url(self.domain)
            
            # Run ffuf with proper flags
            logger.info("\033[92m[+] Running ffuf...\033[0m")
            txt_file = os.path.join(self.output_dir, f"directory_scan_{self.timestamp}.txt")
            
            # Run ffuf and save output to txt file
            ffuf_cmd = f"ffuf -w {self.wordlist} -u {formatted_domain}/FUZZ -ic -v -fc 404,400 > {txt_file}"
            process = await asyncio.create_subprocess_shell(
                ffuf_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            # Check if file exists and has content
            if os.path.exists(txt_file) and os.path.getsize(txt_file) > 0:
                logger.info(f"\033[92m[+] Results saved to {txt_file}\033[0m")
                
                # Convert txt to JSON
                results = self.convert_txt_to_json(txt_file, "Directory")
                
                # Check for sensitive files
                await self._check_sensitive_files()
                
                return results
            else:
                logger.warning("\033[93m[!] No output from ffuf\033[0m")
                return []
            
        except Exception as e:
            logger.error(f"\033[91m[!] Error during directory scanning: {str(e)}\033[0m")
            return []

    async def _check_sensitive_files(self):
        logger.info("\033[92m[+] Checking for sensitive files...\033[0m")
        try:
            # Use quickhits.txt wordlist for sensitive files from config
            sensitive_wordlist = self.config.get_wordlist('sensitive')
            
            if not os.path.exists(sensitive_wordlist):
                logger.error(f"\033[91m[!] Wordlist not found: {sensitive_wordlist}\033[0m")
                return []

            # Format URL using Config
            formatted_domain = self.config.format_url(self.domain)

            # Run ffuf for sensitive files
            txt_file = os.path.join(self.output_dir, f"sensitive_files_{self.timestamp}.txt")
            
            # Run ffuf and save output to txt file
            ffuf_cmd = f"ffuf -w {sensitive_wordlist} -u {formatted_domain}/FUZZ -ic -v -fc 404,400 > {txt_file}"
            process = await asyncio.create_subprocess_shell(
                ffuf_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            # Check if file exists and has content
            if os.path.exists(txt_file) and os.path.getsize(txt_file) > 0:
                logger.info(f"\033[92m[+] Results saved to {txt_file}\033[0m")
                
                # Convert txt to JSON
                self.convert_txt_to_json(txt_file, "Files")
            else:
                logger.warning("\033[93m[!] No output from ffuf\033[0m")
            
        except Exception as e:
            logger.error(f"\033[91m[!] Error checking sensitive files: {str(e)}\033[0m") 