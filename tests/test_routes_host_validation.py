from pathlib import Path
import sys
import socket

sys.path.append(str(Path(__file__).resolve().parents[1]))

from api.routes import _is_private_or_local_host


def test_private_literal_ip_is_blocked():
    assert _is_private_or_local_host("10.10.10.10") is True


def test_hostname_resolving_to_private_ip_is_blocked(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.15", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fd00::1", 0, 0, 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert _is_private_or_local_host("internal.corp") is True


def test_hostname_resolving_to_public_ip_is_allowed(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert _is_private_or_local_host("example.com") is False


def test_invalid_idna_hostname_is_blocked(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        raise UnicodeEncodeError("idna", "foo..bar", 0, 1, "bad label")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert _is_private_or_local_host("foo..bar") is True
