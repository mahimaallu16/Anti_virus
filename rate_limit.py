from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request, Response
from fastapi.responses import JSONResponse

# Rate limit configurations
SCAN_RATE_LIMIT = "5/minute"
API_RATE_LIMIT = "60/minute"
LOGIN_RATE_LIMIT = "5/minute"

# Initialize limiter with memory storage
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[API_RATE_LIMIT]
)

def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> Response:
    return JSONResponse(
        status_code=429,
        content={"detail": f"Rate limit exceeded: {exc.detail}"}
    ) 