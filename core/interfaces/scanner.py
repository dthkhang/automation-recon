from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime

class ScannerInterface(ABC):
    """Base interface for all scanners."""
    
    def __init__(self, domain: str, output_dir: str):
        self.domain = domain
        self.output_dir = output_dir
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.results: Dict[str, Any] = {}
    
    @abstractmethod
    async def scan(self) -> Dict[str, Any]:
        """Perform the scanning operation."""
        pass
    
    @abstractmethod
    async def save_results(self) -> None:
        """Save scan results to files."""
        pass
    
    @abstractmethod
    async def validate_input(self) -> bool:
        """Validate input parameters."""
        pass
    
    async def start(self) -> None:
        """Start the scanning process."""
        self.start_time = datetime.now()
    
    async def end(self) -> None:
        """End the scanning process."""
        self.end_time = datetime.now()
    
    def get_duration(self) -> float:
        """Get the duration of the scan in seconds."""
        if not self.start_time or not self.end_time:
            return 0.0
        return (self.end_time - self.start_time).total_seconds()

class ResultProcessorInterface(ABC):
    """Interface for processing scan results."""
    
    @abstractmethod
    async def process(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Process the scan results."""
        pass
    
    @abstractmethod
    async def validate_results(self, results: Dict[str, Any]) -> bool:
        """Validate the processed results."""
        pass

class CacheInterface(ABC):
    """Interface for caching scan results."""
    
    @abstractmethod
    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cached results by key."""
        pass
    
    @abstractmethod
    async def set(self, key: str, value: Dict[str, Any]) -> None:
        """Set results in cache."""
        pass
    
    @abstractmethod
    async def delete(self, key: str) -> None:
        """Delete cached results."""
        pass
    
    @abstractmethod
    async def clear(self) -> None:
        """Clear all cached results."""
        pass

class MetricsInterface(ABC):
    """Interface for collecting scan metrics."""
    
    @abstractmethod
    async def record_request(self, endpoint: str, status: int, duration: float) -> None:
        """Record a request metric."""
        pass
    
    @abstractmethod
    async def record_error(self, error_type: str, message: str) -> None:
        """Record an error metric."""
        pass
    
    @abstractmethod
    async def get_metrics(self) -> Dict[str, Any]:
        """Get all collected metrics."""
        pass
    
    @abstractmethod
    async def reset_metrics(self) -> None:
        """Reset all metrics."""
        pass 