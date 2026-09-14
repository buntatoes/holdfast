from __future__ import annotations

import pytest

from holdfast_edge.fingerprints import normalize_path


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("/health", "/health"),
        ("/health/", "/health"),
        ("/health/live", "/health/live"),
        ("/healthcare", "/healthcare"),
        ("/health/../admin", "/admin"),
        ("/health/./live", "/health/live"),
        ("/health/%2e%2e/admin", "/admin"),
        ("/health/%2e%2e%2fadmin", "/admin"),
        ("/health%2f%2e%2e%2fadmin", "/admin"),
        ("/health/%2E%2E/admin", "/admin"),
        ("/health/%252e%252e/admin", "/admin"),
        ("/health/%252e%252e%252fadmin", "/admin"),
        ("/%2e%2e/etc/passwd", "/etc/passwd"),
        ("/assets/../secret", "/secret"),
        ("/a/b/../../c", "/c"),
        ("health", "/health"),
        ("/", "/"),
        ("", "/"),
        ("/health?x=1", "/health"),
        ("/health#frag", "/health"),
        ("/health/%2e%2e/admin?x=1", "/admin"),
    ],
)
def test_normalize_path(raw: str, expected: str) -> None:
    assert normalize_path(raw) == expected


def test_normalize_path_never_escapes_root() -> None:
    assert normalize_path("/../../etc/passwd") == "/etc/passwd"
    assert normalize_path("/%2e%2e/%2e%2e/etc/passwd") == "/etc/passwd"
