import os
from typing import Dict, List
from datetime import datetime

class Config:
    # Base paths
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    WORDLIST_DIR = os.path.join(BASE_DIR, "wordlist", "SecLists")
    RESULTS_DIR = os.path.join(BASE_DIR, "results")
    
    # Wordlists
    WORDLISTS: Dict[str, List[str]] = {
        'directory': [
            os.path.join(WORDLIST_DIR, "Discovery/Web-Content/raft-large-directories.txt"),
        ],
        'subdomains': [
            os.path.join(WORDLIST_DIR, "Discovery/DNS/subdomains-top1million-20000.txt")
        ],
        'sensitive': [
            os.path.join(WORDLIST_DIR, "Discovery/Web-Content/quickhits.txt")
        ],
        'technology': [
            os.path.join(WORDLIST_DIR, "Discovery/Web-Content/web-all-content-types.txt")
        ]
    }
    
    # Sensitive files to check
    SENSITIVE_FILES: List[str] = [
        '.git/HEAD',
        '.env',
        'config.php',
        'wp-config.php',
        'robots.txt',
        'sitemap.xml',
        '.DS_Store',
        'crossdomain.xml',
        'phpinfo.php',
        'server-status',
        'server-info'
    ]
    
    # Scanning configuration
    SCAN_TIMEOUT: int = 30
    MAX_CONCURRENT_REQUESTS: int = 2
    RATE_LIMIT: int = 10  # requests per second
    MAX_RETRIES: int = 3
    RETRY_DELAY: int = 1  # seconds
    
    # Cache configuration
    CACHE_DIR: str = os.path.join(BASE_DIR, "cache")
    CACHE_EXPIRY: int = 3600  # 1 hour
    
    # Logging configuration
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_FILE: str = os.path.join(BASE_DIR, "logs", "recon.log")
    
    # Security configuration
    MAX_REQUESTS_PER_IP: int = 100  # per minute
    USER_AGENT: str = "ReconScanner/1.0"
    VERIFY_SSL: bool = True
    
    # Performance configuration
    CONNECTION_POOL_SIZE: int = 10
    DNS_CACHE_TTL: int = 300  # 5 minutes
    
    @classmethod
    def get_wordlist(cls, category: str) -> str:
        """Get wordlist path for a specific category."""
        wordlists = cls.WORDLISTS.get(category, [])
        if not wordlists:
            raise ValueError(f"No wordlist found for category: {category}")
        
        wordlist = wordlists[0]
        if not os.path.exists(wordlist):
            raise FileNotFoundError(f"Wordlist file not found: {wordlist}")
            
        return wordlist
    
    @classmethod
    def get_sensitive_files(cls) -> List[str]:
        """Get list of sensitive files to check."""
        return cls.SENSITIVE_FILES
    
    @classmethod
    def ensure_directories(cls) -> None:
        """Ensure all required directories exist."""
        # Create results directory in project folder
        results_dir = os.path.join(cls.BASE_DIR, "results")
        os.makedirs(results_dir, exist_ok=True)
        
        # Create other required directories
        directories = [
            cls.CACHE_DIR,
            os.path.dirname(cls.LOG_FILE)
        ]
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
    
    @classmethod
    def format_url(cls, url: str) -> str:
        """Format URL by adding http:// or https:// if not present."""
        if not url.startswith(('http://', 'https://')):
            # Try https first, if fails then use http
            try:
                import requests
                response = requests.head(f"https://{url}", timeout=5, verify=False)
                if response.status_code in [200, 301, 302]:
                    return f"https://{url}"
            except:
                pass
            return f"http://{url}"
        return url

    @classmethod
    def get_target_dir(cls, target: str) -> str:
        """Get target directory path."""
        return os.path.join(cls.RESULTS_DIR, target)
    
    @classmethod
    def get_scan_dir(cls, target: str) -> str:
        """Get directory path for a specific scan of a target."""
        target_dir = cls.get_target_dir(target)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_dir = os.path.join(target_dir, timestamp)
        os.makedirs(scan_dir, exist_ok=True)
        return scan_dir 