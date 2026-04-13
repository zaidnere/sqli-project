import time
from fastapi import Request


async def logging_middleware(request: Request, call_next):
    start_time = time.time()

    response = await call_next(request)

    duration = (time.time() - start_time) * 1000

    method = request.method
    path = request.url.path
    status_code = response.status_code
    client_ip = request.client.host if request.client else "unknown"

    print(f"{method} {path} -> {status_code} ({duration:.2f}ms) | IP: {client_ip}")

    return response