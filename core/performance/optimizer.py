import logging
import asyncio
import aiohttp
import dns.resolver
import time
import psutil
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from ..config.config import Config
from ..interfaces.scanner import ScannerInterface

logger = logging.getLogger(__name__)

class PerformanceOptimizer:
    """Optimize performance of scanning operations."""
    
    def __init__(self):
        self.connection_pool = None
        self.dns_cache = {}
        self.dns_cache_ttl = Config.DNS_CACHE_TTL
        self.connection_pool_size = Config.CONNECTION_POOL_SIZE
        self.semaphore = asyncio.Semaphore(5)  # Limit concurrent operations
        self.rate_limiter = asyncio.Semaphore(10)  # Rate limiting
        self.cache = {}
        self.cache_timeout = 3600  # 1 hour cache timeout
        self.start_time = None  # Initialize start_time as None
        self.end_time = None  # Initialize end_time as None
        self.resource_usage = {
            'cpu_percent': [],
            'memory_percent': [],
            'disk_io': [],
            'network_io': []
        }
        self.process = None  # Initialize process as None
    
    async def initialize(self):
        """Initialize connection pool and other resources."""
        try:
            # Initialize connection pool
            self.connection_pool = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(
                    limit=self.connection_pool_size,
                    ttl_dns_cache=self.dns_cache_ttl
                )
            )
            logger.info("Connection pool initialized")
            self.start_time = datetime.now()
            self.resource_usage = {
                'cpu_percent': [],
                'memory_percent': [],
                'disk_io': [],
                'network_io': []
            }
            self.process = psutil.Process()
            logger.info("\033[92m[+] Performance optimizer initialized\033[0m")
        except Exception as e:
            logger.error(f"Error initializing connection pool: {str(e)}")
            raise
    
    async def cleanup(self):
        """Clean up resources."""
        try:
            if self.connection_pool:
                await self.connection_pool.close()
            self.dns_cache.clear()
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            logger.info(f"\033[92m[+] Scan completed in {duration:.2f} seconds\033[0m")
        except Exception as e:
            logger.error(f"Error cleaning up resources: {str(e)}")
    
    async def get_connection(self) -> aiohttp.ClientSession:
        """Get a connection from the pool."""
        if not self.connection_pool:
            await self.initialize()
        return self.connection_pool
    
    async def resolve_dns(self, domain: str) -> List[str]:
        """Resolve DNS with caching."""
        try:
            # Check cache
            if domain in self.dns_cache:
                cache_entry = self.dns_cache[domain]
                if datetime.now() < cache_entry['expires_at']:
                    return cache_entry['ips']
            
            # Resolve DNS
            answers = dns.resolver.resolve(domain, 'A')
            ips = [str(rdata) for rdata in answers]
            
            # Update cache
            self.dns_cache[domain] = {
                'ips': ips,
                'expires_at': datetime.now().timestamp() + self.dns_cache_ttl
            }
            
            return ips
            
        except Exception as e:
            logger.error(f"DNS resolution error: {str(e)}")
            return []
    
    async def optimize_scanner(self, scanner: ScannerInterface) -> None:
        """Optimize a scanner instance."""
        try:
            # Set up connection pool
            scanner.session = await self.get_connection()
            
            # Set up DNS cache
            scanner.dns_cache = self.dns_cache
            
            # Set up semaphore for concurrent operations
            scanner.semaphore = self.semaphore
            
            logger.info(f"Scanner {scanner.__class__.__name__} optimized")
            
        except Exception as e:
            logger.error(f"Error optimizing scanner: {str(e)}")
            raise
    
    async def batch_process(self, items: List[Any], processor: callable, batch_size: int = 10) -> List[Any]:
        """Process items in batches for better performance."""
        try:
            results = []
            for i in range(0, len(items), batch_size):
                batch = items[i:i + batch_size]
                batch_results = await asyncio.gather(*[processor(item) for item in batch])
                results.extend(batch_results)
            return results
        except Exception as e:
            logger.error(f"Batch processing error: {str(e)}")
            raise
    
    async def retry_with_backoff(self, func: callable, *args, max_retries: int = 3, **kwargs) -> Any:
        """Retry operation with exponential backoff."""
        for attempt in range(max_retries):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                delay = (2 ** attempt) * 1  # Exponential backoff
                await asyncio.sleep(delay)
    
    async def measure_performance(self, func: callable, *args, **kwargs) -> Dict[str, Any]:
        """Measure performance of a function."""
        try:
            start_time = datetime.now()
            result = await func(*args, **kwargs)
            end_time = datetime.now()
            
            duration = (end_time - start_time).total_seconds()
            
            return {
                'duration': duration,
                'result': result,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Performance measurement error: {str(e)}")
            raise
    
    async def optimize_memory(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize memory usage of data structures."""
        try:
            optimized = {}
            
            for key, value in data.items():
                if isinstance(value, list):
                    # Convert large lists to sets if order doesn't matter
                    if len(value) > 1000 and all(isinstance(x, (str, int)) for x in value):
                        optimized[key] = list(set(value))
                    else:
                        optimized[key] = value
                elif isinstance(value, dict):
                    optimized[key] = await self.optimize_memory(value)
                else:
                    optimized[key] = value
            
            return optimized
            
        except Exception as e:
            logger.error(f"Memory optimization error: {str(e)}")
            return data
    
    async def compress_results(self, results: Dict[str, Any]) -> bytes:
        """Compress results for storage."""
        try:
            import json
            import zlib
            
            json_data = json.dumps(results)
            compressed = zlib.compress(json_data.encode())
            return compressed
            
        except Exception as e:
            logger.error(f"Results compression error: {str(e)}")
            raise
    
    async def decompress_results(self, compressed_data: bytes) -> Dict[str, Any]:
        """Decompress results from storage."""
        try:
            import json
            import zlib
            
            decompressed = zlib.decompress(compressed_data)
            return json.loads(decompressed.decode())
            
        except Exception as e:
            logger.error(f"Results decompression error: {str(e)}")
            raise
    
    async def optimize_network_requests(self, urls: List[str], timeout: int = 30) -> List[Dict[str, Any]]:
        """Optimize network requests with connection pooling and timeouts."""
        try:
            session = await self.get_connection()
            results = []
            
            async def fetch_url(url: str) -> Dict[str, Any]:
                try:
                    async with session.get(url, timeout=timeout) as response:
                        return {
                            'url': url,
                            'status': response.status,
                            'headers': dict(response.headers)
                        }
                except Exception as e:
                    return {
                        'url': url,
                        'error': str(e)
                    }
            
            # Process URLs in batches
            batch_size = min(50, len(urls))
            for i in range(0, len(urls), batch_size):
                batch = urls[i:i + batch_size]
                batch_results = await asyncio.gather(*[fetch_url(url) for url in batch])
                results.extend(batch_results)
            
            return results
            
        except Exception as e:
            logger.error(f"Network optimization error: {str(e)}")
            raise
    
    async def run_command_async(self, command: str) -> List[str]:
        """Run a command asynchronously with rate limiting."""
        async with self.rate_limiter:
            try:
                process = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0:
                    return stdout.decode().splitlines()
                else:
                    logger.error(f"\033[91m[!] Command failed: {command}\033[0m")
                    logger.error(f"\033[91m[!] Error: {stderr.decode()}\033[0m")
                    return []
            except Exception as e:
                logger.error(f"\033[91m[!] Error running command: {str(e)}\033[0m")
                return []
    
    async def optimize_request(self, url: str, method: str = 'GET', headers: Optional[Dict] = None) -> Dict[str, Any]:
        """Optimize HTTP requests with caching and rate limiting."""
        async with self.rate_limiter:
            # Check cache first
            cache_key = f"{method}:{url}"
            if cache_key in self.cache:
                cache_entry = self.cache[cache_key]
                if (datetime.now() - cache_entry['timestamp']).total_seconds() < self.cache_timeout:
                    return cache_entry['data']
            
            # Make request if not in cache
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.request(method, url, headers=headers) as response:
                        data = await response.json()
                        
                        # Cache the result
                        self.cache[cache_key] = {
                            'data': data,
                            'timestamp': datetime.now()
                        }
                        
                        return data
            except Exception as e:
                logger.error(f"\033[91m[!] Error making request: {str(e)}\033[0m")
                return {}
    
    async def optimize_dns_query(self, domain: str, record_type: str = 'A') -> List[str]:
        """Optimize DNS queries with caching."""
        cache_key = f"dns:{domain}:{record_type}"
        if cache_key in self.cache:
            cache_entry = self.cache[cache_key]
            if (datetime.now() - cache_entry['timestamp']).total_seconds() < self.cache_timeout:
                return cache_entry['data']
        
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results = [str(rdata) for rdata in answers]
            
            # Cache the result
            self.cache[cache_key] = {
                'data': results,
                'timestamp': datetime.now()
            }
            
            return results
        except Exception as e:
            logger.error(f"\033[91m[!] Error querying DNS: {str(e)}\033[0m")
            return []
    
    async def optimize_port_scan(self, host: str, ports: List[int]) -> Dict[int, str]:
        """Optimize port scanning with concurrent operations."""
        async def scan_port(port: int) -> Optional[Tuple[int, str]]:
            try:
                reader, writer = await asyncio.open_connection(host, port)
                writer.close()
                await writer.wait_closed()
                return port, "open"
            except:
                return None
        
        tasks = [scan_port(port) for port in ports]
        results = await asyncio.gather(*tasks)
        return {port: status for port, status in results if port is not None} 