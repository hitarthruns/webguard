import httpx
from urllib.parse import urlparse
from fastapi import Request, Response
from fastapi.responses import StreamingResponse
from config import BACKEND_URL

async def forward_request(request: Request, body_bytes: bytes) -> Response:
    """
    Forwards the incoming FastAPI request to the target backend URL.
    Uses httpx.AsyncClient to execute the request and stream back the response.
    """
    # Build target URL
    url = f"{BACKEND_URL.rstrip('/')}{request.url.path}"
    if request.url.query:
        url += f"?{request.url.query}"

    # Prepare forwarding headers
    headers = dict(request.headers)
    
    # Update Host header to the target backend domain/port
    backend_parts = urlparse(BACKEND_URL)
    headers["host"] = backend_parts.netloc
    
    # Remove Content-Length so httpx can recalculate it correctly based on the body bytes
    headers.pop("content-length", None)
    
    # Add proxy forwarding headers
    client_ip = request.client.host if request.client else "127.0.0.1"
    if "x-forwarded-for" in headers:
        headers["x-forwarded-for"] = f"{headers['x-forwarded-for']}, {client_ip}"
    else:
        headers["x-forwarded-for"] = client_ip
    headers["x-forwarded-proto"] = request.url.scheme

    # Set up client and execute request
    client = httpx.AsyncClient(timeout=10.0, follow_redirects=False)
    
    try:
        # Build the proxy request
        proxy_req = client.build_request(
            method=request.method,
            url=url,
            headers=headers,
            content=body_bytes
        )
        
        # Send request with streaming response
        response = await client.send(proxy_req, stream=True)
        
        # Create generator to stream the response content
        async def stream_response():
            try:
                async for chunk in response.aiter_bytes():
                    yield chunk
            finally:
                # Always close the response and client to release sockets
                await response.aclose()
                await client.aclose()

        # Build response headers to return, skipping transfer/content encodings that httpx/FastAPI handle
        excluded_headers = ["content-encoding", "content-length", "transfer-encoding", "connection"]
        resp_headers = {
            k: v for k, v in response.headers.items()
            if k.lower() not in excluded_headers
        }

        return StreamingResponse(
            stream_response(),
            status_code=response.status_code,
            headers=resp_headers,
            media_type=response.headers.get("content-type")
        )
        
    except httpx.ConnectError:
        await client.aclose()
        return Response(
            content="502 Bad Gateway: MiniWAF could not reach the backend server.",
            status_code=502
        )
    except Exception as e:
        await client.aclose()
        return Response(
            content=f"500 WAF Error: Proxy failed with exception: {str(e)}",
            status_code=500
        )
