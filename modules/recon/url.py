import os, json, asyncio, logging
from datetime import datetime
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse, parse_qs
from .utils import prepare_url, run_command_async
from core.config.config import Config
from core.interfaces.scanner import ScannerInterface
from core.performance.optimizer import PerformanceOptimizer
import re
import subprocess

logger = logging.getLogger(__name__)

class URLScanner(ScannerInterface):
    """Find URLs and endpoints of the target domain."""
    
    def __init__(self, domain: str, output_dir: str):
        super().__init__(domain, output_dir)
        self.optimizer = PerformanceOptimizer()
        self.config = Config()
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.urls: List[Dict] = []
        
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

    async def save_results(self, urls: List[Dict[str, Any]]) -> None:
        """Save URL scanning results to files."""
        try:
            # Prepare results
            results = {
                'timestamp': datetime.now().isoformat(),
                'domain': self.domain,
                'total_urls': len(urls),
                'urls': urls
            }
            
            # Save JSON output
            json_file = os.path.join(self.output_dir, f"url_info_{self.timestamp}.json")
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
                
            # Save human-readable output
            txt_file = os.path.join(self.output_dir, f"url_info_{self.timestamp}.txt")
            with open(txt_file, 'w', encoding='utf-8') as f:
                f.write("URL Scanning Results\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Domain: {self.domain}\n")
                f.write(f"Total URLs: {len(urls)}\n")
                f.write(f"Scan Time: {results['timestamp']}\n\n")
                
                for url in urls:
                    f.write(f"URL: {url['url']}\n")
                    f.write(f"Status Code: {url.get('status_code', 'N/A')}\n")
                    f.write(f"Content Length: {url.get('content_length', 'N/A')}\n")
                    f.write(f"Content Type: {url.get('content_type', 'N/A')}\n")
                    f.write(f"Server: {url.get('server', 'N/A')}\n")
                    f.write(f"Title: {url.get('title', 'N/A')}\n")
                    f.write("-" * 50 + "\n\n")
                    
            logger.info(f"Results saved to {self.output_dir}/")
            
        except Exception as e:
            logger.error(f"Error saving results: {str(e)}")

    def _categorize_urls(self, urls: List[str]) -> Dict[str, List[str]]:
        """Categorize URLs based on their characteristics."""
        categories = {
            'api_endpoints': [],
            'static_files': [],
            'admin_pages': [],
            'auth_related': [],
            'file_uploads': [],
            'user_content': [],
            'interesting_endpoints': [],
            'backup_files': [],
            'config_files': [],
            'debug_pages': [],
            'others': []
        }
        
        static_extensions = {'.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.ttf'}
        interesting_extensions = {'.php', '.asp', '.aspx', '.jsp', '.jspx', '.do', '.action', '.json', '.xml'}
        backup_extensions = {'.bak', '.backup', '.old', '.temp', '.tmp', '.swp', '.save', '.~'}
        config_files = {'.env', '.htaccess', 'config.', 'settings.', 'web.config', 'robots.txt', 'sitemap.xml'}
        
        for url in urls:
            path = urlparse(url).path.lower()
            query = urlparse(url).query.lower()
            
            # Categorize based on path and patterns
            if any(path.endswith(ext) for ext in static_extensions):
                categories['static_files'].append(url)
            elif '/api/' in path or '/v1/' in path or '/v2/' in path:
                categories['api_endpoints'].append(url)
            elif any(admin in path for admin in ['/admin', '/dashboard', '/manage', '/management', '/console']):
                categories['admin_pages'].append(url)
            elif any(auth in path for auth in ['/login', '/register', '/auth', '/oauth', '/signin', '/signup', '/reset']):
                categories['auth_related'].append(url)
            elif '/upload' in path or '/file' in path or 'upload' in query:
                categories['file_uploads'].append(url)
            elif '/user' in path or '/profile' in path or '/account' in path:
                categories['user_content'].append(url)
            elif any(path.endswith(ext) for ext in interesting_extensions):
                categories['interesting_endpoints'].append(url)
            elif any(path.endswith(ext) for ext in backup_extensions) or 'backup' in path:
                categories['backup_files'].append(url)
            elif any(conf in path for conf in config_files):
                categories['config_files'].append(url)
            elif 'debug=true' in query or 'debug=1' in query or '/debug/' in path or '/test/' in path:
                categories['debug_pages'].append(url)
            else:
                categories['others'].append(url)
        
        return {k: v for k, v in categories.items() if v}  # Remove empty categories

    def _extract_parameters(self, urls: List[str]) -> Dict[str, Any]:
        """Extract and analyze parameters from URLs."""
        params_info = {
            'all_params': set(),
            'by_type': {
                'id': set(),
                'file': set(),
                'path': set(),
                'search': set(),
                'filter': set(),
                'sort': set(),
                'page': set(),
                'sensitive': set(),
                'others': set()
            },
            'with_samples': {},
            'frequency': {}
        }
        
        sensitive_keywords = {'password', 'token', 'key', 'secret', 'auth', 'api', 'access', 'pwd', 'hash'}
        
        for url in urls:
            query = urlparse(url).query
            if not query:
                continue
                
            for param in query.split('&'):
                if '=' not in param:
                    continue
                    
                param_name, param_value = param.split('=', 1)
                param_name = param_name.lower()
                
                # Add to all parameters
                params_info['all_params'].add(param_name)
                
                # Count frequency
                params_info['frequency'][param_name] = params_info['frequency'].get(param_name, 0) + 1
                
                # Store sample value if not too long
                if len(param_value) < 100 and param_value not in {'', '1', '0', 'true', 'false'}:
                    if param_name not in params_info['with_samples']:
                        params_info['with_samples'][param_name] = set()
                    params_info['with_samples'][param_name].add(param_value)
                
                # Categorize parameter
                if any(keyword in param_name for keyword in sensitive_keywords):
                    params_info['by_type']['sensitive'].add(param_name)
                elif 'id' in param_name or param_name.endswith('id'):
                    params_info['by_type']['id'].add(param_name)
                elif 'file' in param_name or param_name.endswith(('file', 'path', 'url')):
                    params_info['by_type']['file'].add(param_name)
                elif 'path' in param_name:
                    params_info['by_type']['path'].add(param_name)
                elif any(search in param_name for search in ('search', 'query', 'q', 'find')):
                    params_info['by_type']['search'].add(param_name)
                elif any(filter_key in param_name for filter_key in ('filter', 'where', 'select')):
                    params_info['by_type']['filter'].add(param_name)
                elif any(sort_key in param_name for sort_key in ('sort', 'order', 'orderby')):
                    params_info['by_type']['sort'].add(param_name)
                elif any(page_key in param_name for page_key in ('page', 'offset', 'limit')):
                    params_info['by_type']['page'].add(param_name)
                else:
                    params_info['by_type']['others'].add(param_name)
        
        # Convert sets to sorted lists for JSON serialization
        params_info['all_params'] = sorted(params_info['all_params'])
        for param_type in params_info['by_type']:
            params_info['by_type'][param_type] = sorted(params_info['by_type'][param_type])
        for param in params_info['with_samples']:
            params_info['with_samples'][param] = sorted(params_info['with_samples'][param])
        
        return params_info

    async def enumerate_urls(self) -> List[Dict[str, Any]]:
        """Enumerate URLs using gau and httpx."""
        try:
            logger.info("\033[92m[+] Running gau...\033[0m")
            
            # Format domain using Config
            formatted_domain = self.config.format_url(self.domain)
            
            # Run gau to get URLs
            gau_cmd = f"gau {formatted_domain}"
            gau_result = subprocess.run(gau_cmd, shell=True, capture_output=True, text=True)
            
            if gau_result.returncode != 0:
                logger.error(f"\033[91m[!] Command failed: {gau_cmd}\033[0m")
                logger.error(f"\033[91m[!] Error: {gau_result.stderr}\033[0m")
                return []
                
            # Process results
            urls = []
            for line in gau_result.stdout.splitlines():
                if line.strip() and line.startswith(('http://', 'https://')):
                    urls.append({
                        "url": line.strip(),
                        "timestamp": datetime.now().isoformat()
                    })
                        
            if not urls:
                logger.info("\033[93m[!] No URLs found\033[0m")
            else:
                logger.info(f"\033[91m[+] Found {len(urls)} URLs\033[0m")
                
            return urls
            
        except Exception as e:
            logger.error(f"\033[91m[!] Error enumerating URLs: {str(e)}\033[0m")
            return []

    async def scan(self) -> Dict[str, Any]:
        """Run the complete URL scanning process."""
        try:
            logger.info("\033[92m[+] Starting URL scanning...\033[0m")
            
            # Format URL using Config
            formatted_domain = self.config.format_url(self.domain)
            
            # Run gau
            logger.info("\033[92m[+] Running gau...\033[0m")
            gau_cmd = f"gau --subs --threads 5 --timeout 10 {formatted_domain}"
            gau_result = subprocess.run(gau_cmd, shell=True, capture_output=True, text=True)
            
            if gau_result.returncode != 0:
                logger.error(f"\033[91m[!] Error running gau: {gau_result.stderr}\033[0m")
                return {}
            
            # Process results
            urls = []
            seen_urls = set()  # Track unique URLs
            
            for line in gau_result.stdout.splitlines():
                url = line.strip()
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    url_info = {
                        "url": url,
                        "timestamp": datetime.now().isoformat()
                    }
                    urls.append(url_info)
                    
            if urls:
                logger.info(f"\033[92m[+] Found {len(urls)} unique URLs\033[0m")
            else:
                logger.info("\033[93m[!] No URLs found\033[0m")
                        
            # Save results
            await self.save_results(urls)
            logger.info(f"\033[92m[+] Results saved to {self.output_dir}/\033[0m")
            
            return urls
            
        except Exception as e:
            logger.error(f"\033[91m[!] Error during URL scanning: {str(e)}\033[0m")
            return {} 