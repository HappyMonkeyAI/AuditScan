from repo_audit_scan import external_fetch


class _Headers(dict):
    def __init__(self, mime: str, length: str | None):
        super().__init__({"Content-Length": length} if length else {})
        self._mime = mime

    def get_content_type(self):
        return self._mime


class _Response:
    def __init__(self, body: bytes, mime: str, length: str | None = None):
        self._body = body
        self.headers = _Headers(mime, length)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit):
        return self._body[:limit]


def test_external_fetch_rejects_oversized_body(monkeypatch):
    monkeypatch.setattr(external_fetch, "validate_external_url", lambda url: None)
    monkeypatch.setattr(external_fetch, "urlopen", lambda *args, **kwargs: _Response(b"x" * (external_fetch._MAX_BYTES + 1), "text/plain"))
    result = external_fetch.fetch_external_text("https://example.com/large")
    assert result.status == "needs_human_review"
    assert result.reason == "response exceeds size limit"
    assert result.content == ""


def test_external_fetch_rejects_binary_mime_without_reading_body(monkeypatch):
    read = {"called": False}
    response = _Response(b"binary", "application/octet-stream")
    original = response.read

    def guarded_read(limit):
        read["called"] = True
        return original(limit)

    response.read = guarded_read
    monkeypatch.setattr(external_fetch, "validate_external_url", lambda url: None)
    monkeypatch.setattr(external_fetch, "urlopen", lambda *args, **kwargs: response)
    result = external_fetch.fetch_external_text("https://example.com/file.bin")
    assert result.status == "needs_human_review"
    assert result.reason == "unsupported MIME type"
    assert read["called"] is False
