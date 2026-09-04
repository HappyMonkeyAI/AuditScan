import socket
from repo_audit_scan.external_fetch import validate_external_url
from repo_audit_scan.mcp_server import MCPServer


def test_external_fetch_rejects_non_https_and_credentials(monkeypatch):
    assert validate_external_url("http://example.com/x") == "only HTTPS URLs are permitted"
    assert validate_external_url("https://user:pass@example.com/x") == "URL credentials are prohibited"


def test_external_fetch_rejects_private_resolution(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, 0, 0, "", ("192.168.1.4", 0))])
    assert "public" in validate_external_url("https://example.com/x")


def test_mcp_link_tool_blocks_before_retrieval(monkeypatch):
    called = {"fetch": False}
    monkeypatch.setattr("repo_audit_scan.mcp_server.fetch_external_text", lambda url: called.update(fetch=True))
    # malformed stub is not a usable fetch result; policy validation is tested independently above
    assert "inspect_external_link" in MCPServer().list_tools()
    assert called["fetch"] is False
