import os, json, asyncio, logging
from datetime import datetime
from typing import List, Dict, Any
from .utils import prepare_url, run_command_async
from core.config.config import Config
from core.interfaces.scanner import ScannerInterface

logger = logging.getLogger(__name__)

class TechnologyScanner(ScannerInterface):
    """Detect technologies used by the target."""
    
    def __init__(self, domain: str, output_dir: str):
        super().__init__(domain, output_dir)
        self.semaphore = asyncio.Semaphore(2)  # Limit concurrent processes to 2
        self.config = Config()
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session = None
        
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
                'total_technologies': len(results),
                'technologies': results
            }
            
            # Save JSON output
            json_file = os.path.join(self.output_dir, f"tech_info_{self.timestamp}.json")
            with open(json_file, "w", encoding='utf-8') as f:
                json.dump(results_dict, f, indent=2, ensure_ascii=False)
                
            # Save human-readable output
            txt_file = os.path.join(self.output_dir, f"tech_info_{self.timestamp}.txt")
            with open(txt_file, "w", encoding='utf-8') as f:
                f.write("Technology Scanning Results\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Domain: {self.domain}\n")
                f.write(f"Total Technologies: {len(results)}\n")
                f.write(f"Scan Time: {datetime.now().isoformat()}\n\n")
                
                for tech in results:
                    # Handle both webanalyze and error results
                    if 'error' in tech:
                        f.write(f"Error: {tech['error']}\n")
                        if 'raw_output' in tech:
                            f.write("Raw Output:\n")
                            f.write(str(tech['raw_output']))
                    else:
                        # Handle webanalyze results
                        f.write(f"Name: {tech.get('name', 'N/A')}\n")
                        f.write(f"Version: {tech.get('version', 'N/A')}\n")
                        f.write(f"Category: {tech.get('category', 'N/A')}\n")
                        f.write(f"Confidence: {tech.get('confidence', 'N/A')}\n")
                    f.write("-" * 50 + "\n\n")
                    
            logger.info("\033[92m[+] Results saved successfully\033[0m")
            return True
            
        except Exception as e:
            logger.error(f"\033[91m[!] Error saving results: {str(e)}\033[0m")
            return False

    async def scan(self) -> List[Dict[str, Any]]:
        """Run the complete technology scanning process."""
        try:
            logger.info("\033[92m[+] Starting technology scanning...\033[0m")
            
            # Format URL using Config
            formatted_domain = self.config.format_url(self.domain)
            
            # Run webanalyze and save results directly to files
            logger.info("\033[92m[+] Running webanalyze...\033[0m")
            
            # Save to txt file
            txt_file = os.path.join(self.output_dir, f"tech_info_{self.timestamp}.txt")
            webanalyze_cmd = f"webanalyze -host {formatted_domain} > {txt_file}"
            await run_command_async(webanalyze_cmd, self.semaphore, self.output_dir)
            
            # Save to json file
            json_file = os.path.join(self.output_dir, f"tech_info_{self.timestamp}.json")
            webanalyze_json_cmd = f"webanalyze -host {formatted_domain} -output json > {json_file}"
            await run_command_async(webanalyze_json_cmd, self.semaphore, self.output_dir)
            
            logger.info("\033[92m[+] Technology scanning completed\033[0m")
            return []
            
        except Exception as e:
            logger.error(f"\033[91m[!] Error during technology scanning: {str(e)}\033[0m")
            return [] 