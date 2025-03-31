import re, os
import logging
from typing import Dict, Any, Optional
from urllib.parse import urlparse
from ..config.config import Config

logger = logging.getLogger(__name__)

class InputValidator:
    """Validate input parameters for scanning operations."""
    
    @staticmethod
    def validate_domain(domain: str) -> str:
        """Validate and sanitize domain input."""
        try:
            if not domain or not isinstance(domain, str):
                raise ValueError("Domain must be a non-empty string")
            
            # Remove any protocol prefix
            domain = domain.strip().lower()
            if domain.startswith(('http://', 'https://')):
                domain = domain.split('://')[1]
            
            # Basic domain format validation
            if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$', domain):
                raise ValueError("Invalid domain format")
            
            return domain
            
        except Exception as e:
            logger.error(f"Domain validation error: {str(e)}")
            raise
    
    @staticmethod
    def validate_url(url: str) -> str:
        """Validate and sanitize URL input."""
        try:
            if not url or not isinstance(url, str):
                raise ValueError("URL must be a non-empty string")
            
            url = url.strip()
            if not url.startswith(('http://', 'https://')):
                url = f"https://{url}"
            
            parsed = urlparse(url)
            if not parsed.netloc:
                raise ValueError("Invalid URL format")
            
            return url
            
        except Exception as e:
            logger.error(f"URL validation error: {str(e)}")
            raise
    
    @staticmethod
    def validate_output_dir(output_dir: str) -> str:
        """Validate and sanitize output directory path."""
        try:
            if not output_dir or not isinstance(output_dir, str):
                raise ValueError("Output directory must be a non-empty string")
            
            output_dir = output_dir.strip()
            if not os.path.isabs(output_dir):
                output_dir = os.path.join(Config.BASE_DIR, output_dir)
            
            # Ensure directory exists
            os.makedirs(output_dir, exist_ok=True)
            
            return output_dir
            
        except Exception as e:
            logger.error(f"Output directory validation error: {str(e)}")
            raise
    
    @staticmethod
    def validate_port_range(start_port: int, end_port: int) -> tuple:
        """Validate port range."""
        try:
            if not isinstance(start_port, int) or not isinstance(end_port, int):
                raise ValueError("Ports must be integers")
            
            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
                raise ValueError("Ports must be between 1 and 65535")
            
            if start_port > end_port:
                raise ValueError("Start port must be less than or equal to end port")
            
            return start_port, end_port
            
        except Exception as e:
            logger.error(f"Port range validation error: {str(e)}")
            raise
    
    @staticmethod
    def validate_wordlist(wordlist_path: str) -> str:
        """Validate wordlist file path."""
        try:
            if not wordlist_path or not isinstance(wordlist_path, str):
                raise ValueError("Wordlist path must be a non-empty string")
            
            wordlist_path = wordlist_path.strip()
            if not os.path.isabs(wordlist_path):
                wordlist_path = os.path.join(Config.WORDLIST_DIR, wordlist_path)
            
            if not os.path.exists(wordlist_path):
                raise ValueError(f"Wordlist file not found: {wordlist_path}")
            
            return wordlist_path
            
        except Exception as e:
            logger.error(f"Wordlist validation error: {str(e)}")
            raise
    
    @staticmethod
    def validate_scan_options(options: Dict[str, Any]) -> Dict[str, Any]:
        """Validate scan options."""
        try:
            validated_options = {}
            
            # Validate timeout
            if 'timeout' in options:
                timeout = int(options['timeout'])
                if timeout < 1 or timeout > 300:
                    raise ValueError("Timeout must be between 1 and 300 seconds")
                validated_options['timeout'] = timeout
            
            # Validate concurrent requests
            if 'max_concurrent_requests' in options:
                max_requests = int(options['max_concurrent_requests'])
                if max_requests < 1 or max_requests > 10:
                    raise ValueError("Max concurrent requests must be between 1 and 10")
                validated_options['max_concurrent_requests'] = max_requests
            
            # Validate rate limit
            if 'rate_limit' in options:
                rate_limit = int(options['rate_limit'])
                if rate_limit < 1 or rate_limit > 100:
                    raise ValueError("Rate limit must be between 1 and 100 requests per second")
                validated_options['rate_limit'] = rate_limit
            
            return validated_options
            
        except Exception as e:
            logger.error(f"Scan options validation error: {str(e)}")
            raise
    
    @staticmethod
    def validate_results(results: Dict[str, Any]) -> bool:
        """Validate scan results."""
        try:
            required_fields = ['timestamp', 'domain', 'results']
            
            # Check required fields
            for field in required_fields:
                if field not in results:
                    raise ValueError(f"Missing required field: {field}")
            
            # Validate timestamp
            if not isinstance(results['timestamp'], str):
                raise ValueError("Timestamp must be a string")
            
            # Validate domain
            if not isinstance(results['domain'], str):
                raise ValueError("Domain must be a string")
            
            # Validate results
            if not isinstance(results['results'], dict):
                raise ValueError("Results must be a dictionary")
            
            return True
            
        except Exception as e:
            logger.error(f"Results validation error: {str(e)}")
            return False 