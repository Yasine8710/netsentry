"""ASGI middleware that rejects oversized request bodies before they are buffered."""

import json
from collections.abc import Callable

from starlette.types import ASGIApp, Message, Receive, Scope, Send


class _TooLarge(Exception):
    pass


class BodySizeLimitMiddleware:
    """Applies `limit()` bytes to POST/PUT/PATCH bodies on the given path prefix."""

    def __init__(
        self, app: ASGIApp, limit: Callable[[str], int], path_prefix: str = "/api/"
    ) -> None:
        self.app = app
        self.limit = limit
        self.prefix = path_prefix

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope["method"] not in {"POST", "PUT", "PATCH"}
            or not scope["path"].startswith(self.prefix)
        ):
            await self.app(scope, receive, send)
            return

        max_bytes = self.limit(scope["path"])
        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None:
            try:
                if int(declared) > max_bytes:
                    await self._reject(send, max_bytes)
                    return
            except ValueError:
                await self._reject(send, max_bytes, 400, "Invalid Content-Length header.")
                return

        seen = 0
        started = False

        async def counting_receive() -> Message:
            nonlocal seen
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > max_bytes:
                    raise _TooLarge
            return msg

        async def tracking_send(msg: Message) -> None:
            nonlocal started
            if msg["type"] == "http.response.start":
                started = True
            await send(msg)

        try:
            await self.app(scope, counting_receive, tracking_send)
        except _TooLarge:
            if not started:
                await self._reject(send, max_bytes)

    @staticmethod
    async def _reject(send: Send, max_bytes: int, status: int = 413, detail: str | None = None):
        body = json.dumps(
            {"detail": detail or f"Request body exceeds the {max_bytes // (1024 * 1024)} MB limit."}
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"application/json"), (b"connection", b"close")],
            }
        )
        await send({"type": "http.response.body", "body": body})
