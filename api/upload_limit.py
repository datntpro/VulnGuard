"""Chặn request quá lớn TRƯỚC khi Starlette spool body multipart ra đĩa/RAM (M-5).

Content-Length vượt giới hạn → 413 ngay, không đọc body. Body chunked (không có
Content-Length) được đếm byte khi đọc và bị ngắt khi vượt giới hạn."""
from api.config import settings

_MARGIN = 1 << 20  # overhead multipart


class _TooLarge(Exception):
    pass


def _is_upload(scope) -> bool:
    return scope["type"] == "http" and scope["method"] == "POST" and scope["path"].endswith("/scan-upload")


async def _send_413(send):
    body = b'{"detail":"File qu\\u00e1 l\\u1edbn"}'
    await send({"type": "http.response.start", "status": 413,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


class UploadSizeLimitMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if not _is_upload(scope):
            return await self.app(scope, receive, send)
        limit = settings.upload_max_bytes + _MARGIN
        for k, v in scope.get("headers", []):
            if k == b"content-length":
                try:
                    if int(v) > limit:
                        return await _send_413(send)
                except ValueError:
                    return await _send_413(send)
        seen = 0
        started = False

        async def counting_receive():
            nonlocal seen
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > limit:
                    raise _TooLarge()
            return msg

        async def tracking_send(msg):
            nonlocal started
            if msg["type"] == "http.response.start":
                started = True
            await send(msg)

        try:
            await self.app(scope, counting_receive, tracking_send)
        except _TooLarge:
            if not started:
                await _send_413(send)
