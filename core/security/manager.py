import logging, re
import hashlib
import secrets
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
from ..config.config import Config

logger = logging.getLogger(__name__)

class SecurityManager:
    """Manage security-related operations and rate limiting."""
    
    def __init__(self):
        self.rate_limits = defaultdict(list)
        self.blocked_ips = {}
        self.api_keys = {}
        self.session_tokens = {}
    
    def check_rate_limit(self, ip: str) -> bool:
        """Check if an IP has exceeded rate limit."""
        try:
            current_time = datetime.now()
            
            # Clean up old entries
            self.rate_limits[ip] = [
                timestamp for timestamp in self.rate_limits[ip]
                if current_time - timestamp < timedelta(minutes=1)
            ]
            
            # Check if IP is blocked
            if ip in self.blocked_ips:
                if current_time < self.blocked_ips[ip]:
                    return False
                else:
                    del self.blocked_ips[ip]
            
            # Check rate limit
            if len(self.rate_limits[ip]) >= Config.MAX_REQUESTS_PER_IP:
                self.blocked_ips[ip] = current_time + timedelta(minutes=5)
                logger.warning(f"IP {ip} blocked for rate limit violation")
                return False
            
            self.rate_limits[ip].append(current_time)
            return True
            
        except Exception as e:
            logger.error(f"Rate limit check error: {str(e)}")
            return False
    
    def generate_api_key(self, user_id: str) -> str:
        """Generate a new API key for a user."""
        try:
            api_key = secrets.token_urlsafe(32)
            self.api_keys[api_key] = {
                'user_id': user_id,
                'created_at': datetime.now(),
                'last_used': datetime.now()
            }
            return api_key
        except Exception as e:
            logger.error(f"API key generation error: {str(e)}")
            raise
    
    def validate_api_key(self, api_key: str) -> bool:
        """Validate an API key."""
        try:
            if api_key not in self.api_keys:
                return False
            
            key_data = self.api_keys[api_key]
            key_data['last_used'] = datetime.now()
            return True
            
        except Exception as e:
            logger.error(f"API key validation error: {str(e)}")
            return False
    
    def generate_session_token(self, user_id: str) -> str:
        """Generate a new session token."""
        try:
            token = secrets.token_urlsafe(32)
            self.session_tokens[token] = {
                'user_id': user_id,
                'created_at': datetime.now(),
                'expires_at': datetime.now() + timedelta(hours=24)
            }
            return token
        except Exception as e:
            logger.error(f"Session token generation error: {str(e)}")
            raise
    
    def validate_session_token(self, token: str) -> bool:
        """Validate a session token."""
        try:
            if token not in self.session_tokens:
                return False
            
            token_data = self.session_tokens[token]
            if datetime.now() > token_data['expires_at']:
                del self.session_tokens[token]
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Session token validation error: {str(e)}")
            return False
    
    def sanitize_input(self, input_data: Any) -> Any:
        """Sanitize input data to prevent injection attacks."""
        try:
            if isinstance(input_data, str):
                # Remove potentially dangerous characters
                sanitized = re.sub(r'[<>]', '', input_data)
                # Escape special characters
                sanitized = sanitized.replace('"', '\\"').replace("'", "\\'")
                return sanitized
            elif isinstance(input_data, dict):
                return {k: self.sanitize_input(v) for k, v in input_data.items()}
            elif isinstance(input_data, list):
                return [self.sanitize_input(item) for item in input_data]
            return input_data
            
        except Exception as e:
            logger.error(f"Input sanitization error: {str(e)}")
            return input_data
    
    def hash_password(self, password: str) -> str:
        """Hash a password using a secure algorithm."""
        try:
            salt = secrets.token_hex(16)
            hash_obj = hashlib.sha256()
            hash_obj.update((password + salt).encode())
            return f"{salt}:{hash_obj.hexdigest()}"
        except Exception as e:
            logger.error(f"Password hashing error: {str(e)}")
            raise
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        try:
            salt, stored_hash = hashed_password.split(':')
            hash_obj = hashlib.sha256()
            hash_obj.update((password + salt).encode())
            return hash_obj.hexdigest() == stored_hash
        except Exception as e:
            logger.error(f"Password verification error: {str(e)}")
            return False
    
    def validate_ssl_certificate(self, domain: str) -> Dict[str, Any]:
        """Validate SSL certificate for a domain."""
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    is_expired = datetime.now() > not_after
                    
                    # Check issuer
                    issuer = dict(x[0] for x in cert['issuer'])
                    
                    return {
                        'valid': not is_expired,
                        'expires_at': not_after.isoformat(),
                        'issuer': issuer,
                        'version': cert['version'],
                        'serial_number': cert['serialNumber']
                    }
                    
        except Exception as e:
            logger.error(f"SSL certificate validation error: {str(e)}")
            return {
                'valid': False,
                'error': str(e)
            }
    
    def check_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Check security headers in HTTP response."""
        try:
            security_headers = {
                'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'X-XSS-Protection': headers.get('X-XSS-Protection'),
                'Content-Security-Policy': headers.get('Content-Security-Policy'),
                'Referrer-Policy': headers.get('Referrer-Policy'),
                'Permissions-Policy': headers.get('Permissions-Policy')
            }
            
            recommendations = []
            for header, value in security_headers.items():
                if not value:
                    recommendations.append(f"Missing {header}")
                elif header == 'Strict-Transport-Security' and 'max-age' not in value:
                    recommendations.append("HSTS should include max-age directive")
            
            return {
                'headers_present': {k: v is not None for k, v in security_headers.items()},
                'recommendations': recommendations
            }
            
        except Exception as e:
            logger.error(f"Security headers check error: {str(e)}")
            return {'error': str(e)} 