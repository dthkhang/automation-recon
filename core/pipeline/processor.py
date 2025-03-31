from typing import Dict, Any, List
import json
import logging
from datetime import datetime
from ..interfaces.scanner import ResultProcessorInterface
from ..config.config import Config

logger = logging.getLogger(__name__)

class ResultProcessor(ResultProcessorInterface):
    """Process and transform scan results."""
    
    def __init__(self):
        self.processors: List[callable] = []
        self.validation_rules: List[callable] = []
    
    def add_processor(self, processor: callable) -> None:
        """Add a processor function to the pipeline."""
        self.processors.append(processor)
    
    def add_validation_rule(self, rule: callable) -> None:
        """Add a validation rule to the pipeline."""
        self.validation_rules.append(rule)
    
    async def process(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Process results through all registered processors."""
        try:
            processed_results = results.copy()
            
            # Add metadata
            processed_results['metadata'] = {
                'processed_at': datetime.now().isoformat(),
                'processor_version': '1.0'
            }
            
            # Apply all processors
            for processor in self.processors:
                processed_results = await processor(processed_results)
            
            return processed_results
            
        except Exception as e:
            logger.error(f"Error processing results: {str(e)}")
            raise
    
    async def validate_results(self, results: Dict[str, Any]) -> bool:
        """Validate results against all registered rules."""
        try:
            for rule in self.validation_rules:
                if not await rule(results):
                    return False
            return True
        except Exception as e:
            logger.error(f"Error validating results: {str(e)}")
            return False

class JSONFormatter:
    """Format results as JSON."""
    
    @staticmethod
    async def format(results: Dict[str, Any]) -> Dict[str, Any]:
        """Format results as JSON with proper structure."""
        return {
            'timestamp': datetime.now().isoformat(),
            'results': results
        }

class TextFormatter:
    """Format results as human-readable text."""
    
    @staticmethod
    async def format(results: Dict[str, Any]) -> str:
        """Format results as human-readable text."""
        lines = []
        
        # Add header
        lines.append("Scan Results")
        lines.append("=" * 50)
        
        # Add timestamp
        lines.append(f"Timestamp: {datetime.now().isoformat()}")
        lines.append("")
        
        # Process each section
        for section, data in results.items():
            if section == 'metadata':
                continue
                
            lines.append(f"{section.title()}")
            lines.append("-" * len(section))
            
            if isinstance(data, dict):
                for key, value in data.items():
                    lines.append(f"{key}: {value}")
            elif isinstance(data, list):
                for item in data:
                    lines.append(f"- {item}")
            else:
                lines.append(str(data))
            
            lines.append("")
        
        return "\n".join(lines)

class ResultWriter:
    """Write results to files."""
    
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
    
    async def write_json(self, results: Dict[str, Any], filename: str) -> None:
        """Write results to JSON file."""
        filepath = f"{self.output_dir}/{filename}.json"
        try:
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Results written to {filepath}")
        except Exception as e:
            logger.error(f"Error writing JSON results: {str(e)}")
            raise
    
    async def write_text(self, text: str, filename: str) -> None:
        """Write results to text file."""
        filepath = f"{self.output_dir}/{filename}.txt"
        try:
            with open(filepath, 'w') as f:
                f.write(text)
            logger.info(f"Results written to {filepath}")
        except Exception as e:
            logger.error(f"Error writing text results: {str(e)}")
            raise 