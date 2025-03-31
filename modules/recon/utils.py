import asyncio, time, httpx, logging
from typing import Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants
RATE_LIMIT = 10  # requests per second
TIMEOUT = 30  # seconds
MAX_RETRIES = 3
RETRY_DELAY = 1  # seconds

class RateLimiter:
    def __init__(self, calls_per_second):
        self.calls_per_second = calls_per_second
        self.last_call = 0

    async def acquire(self):
        now = time.time()
        if now - self.last_call < 1.0 / self.calls_per_second:
            await asyncio.sleep(1.0 / self.calls_per_second - (now - self.last_call))
        self.last_call = time.time()

async def prepare_url(domain: str) -> str:
    """
    Tự động thêm tiền tố http:// hoặc https:// nếu chưa có
    """
    if not domain.startswith(('http://', 'https://')):
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.head(f'https://{domain}')
                return f'https://{domain}'
        except:
            return f'http://{domain}'
    return domain

async def retry_with_backoff(func, *args, max_retries=MAX_RETRIES, **kwargs):
    for attempt in range(max_retries):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            await asyncio.sleep(RETRY_DELAY * (2 ** attempt))

async def run_command_async(command: str, semaphore: asyncio.Semaphore, output_dir: str) -> list:
    async with semaphore:
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            return stdout.decode().splitlines()
        except Exception as e:
            logger.error(f"Error running command {command}: {str(e)}")
            return [] 