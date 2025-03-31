import logging
from typing import Dict, Any, List
from datetime import datetime
from collections import defaultdict
from ..interfaces.scanner import MetricsInterface
from ..config.config import Config

logger = logging.getLogger(__name__)

class MetricsCollector(MetricsInterface):
    """Collect and track scan metrics."""
    
    def __init__(self):
        self.metrics: Dict[str, Any] = {
            'requests': defaultdict(list),
            'errors': defaultdict(list),
            'start_time': None,
            'end_time': None,
            'total_requests': 0,
            'total_errors': 0,
            'total_duration': 0.0
        }
    
    async def record_request(self, endpoint: str, status: int, duration: float) -> None:
        """Record a request metric."""
        try:
            self.metrics['requests'][endpoint].append({
                'timestamp': datetime.now().isoformat(),
                'status': status,
                'duration': duration
            })
            self.metrics['total_requests'] += 1
            logger.debug(f"Recorded request: {endpoint} - Status: {status} - Duration: {duration}s")
        except Exception as e:
            logger.error(f"Error recording request metric: {str(e)}")
    
    async def record_error(self, error_type: str, message: str) -> None:
        """Record an error metric."""
        try:
            self.metrics['errors'][error_type].append({
                'timestamp': datetime.now().isoformat(),
                'message': message
            })
            self.metrics['total_errors'] += 1
            logger.error(f"Recorded error: {error_type} - {message}")
        except Exception as e:
            logger.error(f"Error recording error metric: {str(e)}")
    
    async def get_metrics(self) -> Dict[str, Any]:
        """Get all collected metrics."""
        try:
            # Calculate summary statistics
            metrics_summary = {
                'summary': {
                    'total_requests': self.metrics['total_requests'],
                    'total_errors': self.metrics['total_errors'],
                    'total_duration': self.metrics['total_duration'],
                    'success_rate': self._calculate_success_rate(),
                    'average_duration': self._calculate_average_duration()
                },
                'requests': dict(self.metrics['requests']),
                'errors': dict(self.metrics['errors'])
            }
            
            return metrics_summary
            
        except Exception as e:
            logger.error(f"Error getting metrics: {str(e)}")
            return {}
    
    async def reset_metrics(self) -> None:
        """Reset all metrics."""
        try:
            self.metrics = {
                'requests': defaultdict(list),
                'errors': defaultdict(list),
                'start_time': None,
                'end_time': None,
                'total_requests': 0,
                'total_errors': 0,
                'total_duration': 0.0
            }
            logger.info("Reset all metrics")
        except Exception as e:
            logger.error(f"Error resetting metrics: {str(e)}")
    
    def _calculate_success_rate(self) -> float:
        """Calculate the success rate of requests."""
        if self.metrics['total_requests'] == 0:
            return 0.0
        
        successful_requests = sum(
            1 for requests in self.metrics['requests'].values()
            for req in requests
            if 200 <= req['status'] < 300
        )
        
        return (successful_requests / self.metrics['total_requests']) * 100
    
    def _calculate_average_duration(self) -> float:
        """Calculate the average duration of requests."""
        if self.metrics['total_requests'] == 0:
            return 0.0
        
        total_duration = sum(
            req['duration']
            for requests in self.metrics['requests'].values()
            for req in requests
        )
        
        return total_duration / self.metrics['total_requests']
    
    def start_tracking(self) -> None:
        """Start tracking metrics."""
        self.metrics['start_time'] = datetime.now()
    
    def end_tracking(self) -> None:
        """End tracking metrics."""
        self.metrics['end_time'] = datetime.now()
        if self.metrics['start_time']:
            self.metrics['total_duration'] = (
                self.metrics['end_time'] - self.metrics['start_time']
            ).total_seconds()
    
    def get_endpoint_stats(self) -> Dict[str, Any]:
        """Get statistics for each endpoint."""
        stats = {}
        for endpoint, requests in self.metrics['requests'].items():
            if requests:
                durations = [req['duration'] for req in requests]
                statuses = [req['status'] for req in requests]
                
                stats[endpoint] = {
                    'total_requests': len(requests),
                    'success_rate': (sum(1 for s in statuses if 200 <= s < 300) / len(statuses)) * 100,
                    'average_duration': sum(durations) / len(durations),
                    'min_duration': min(durations),
                    'max_duration': max(durations),
                    'status_distribution': self._get_status_distribution(statuses)
                }
        return stats
    
    def _get_status_distribution(self, statuses: List[int]) -> Dict[int, int]:
        """Get distribution of status codes."""
        distribution = defaultdict(int)
        for status in statuses:
            distribution[status] += 1
        return dict(distribution) 