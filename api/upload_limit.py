"""Chặn request quá lớn TRƯỚC khi Starlette spool body multipart ra đĩa/RAM (M-5).

Content-Length vượt giới hạn → 413 ngay, không đọc body. Body chunked (không có
Content-Length) được đếm byte khi đọc; vượt giới hạn → middleware tự trả 413 và báo
`http.disconnect` cho app bên trong. Mọi POST/PUT/PATCH đều bị giới hạn:
`/scan-upload` dùng UPLOAD_MAX_BYTES, các route còn lại dùng BODY_MAX_BYTES (RV-4)."""
from api.config import settings

_MARGIN = 1 << 20  # overhead multipart


def _limit_for(scope) -> int | None:
    if scope["type"] != "http" or scope["method"] not in ("POST", "PUT", "PATCH"):
        return None
    if scope["path"].endswith("/scan-upload"):
        return settings.upload_max_bytes + _MARGIN
    return settings.body_max_bytes + _MARGIN


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
        limit = _limit_for(scope)
        if limit is None:
            return await self.app(scope, receive, send)
        for k, v in scope.get("headers", []):
            if k == b"content-length":
                try:
                    if int(v) > limit:
                        return await _send_413(send)
                except ValueError:
                    return await _send_413(send)
        seen = 0
        started = False
        rejected = False

        async def counting_receive():
            nonlocal seen, rejected
            if rejected:
                return {"type": "http.disconnect"}
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > limit:
                    rejected = True
                    if not started:
                        await _send_413(send)
                    return {"type": "http.disconnect"}
            return msg

        async def tracking_send(msg):
            nonlocal started
            if rejected:
                return  # đã trả 413; bỏ phản hồi của app bên trong
            if msg["type"] == "http.response.start":
                started = True
            await send(msg)

        try:
            await self.app(scope, counting_receive, tracking_send)
        except Exception:
            if not rejected:
                raise
