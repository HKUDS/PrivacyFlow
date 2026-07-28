from __future__ import annotations

from gateway.detector_manager import DetectorManager
from gateway.detectors.validators.luhn import luhn_valid


def subtypes(text: str) -> set[str]:
    return {d.subtype for d in DetectorManager().scan(text)}


def test_api_key_detected() -> None:
    assert "api_key" in subtypes("key sk-proj-abcdefghijklmnopqrstuvwxyz123456")


def test_realistic_synthetic_secret_formats_detected() -> None:
    found = subtypes(
        "Key: sk-apgtest-111111111111111111111111111111111111\n"
        "JWT: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n"
        "DATABASE_URL=postgres://admin:apgtest-db-pass@localhost:5432/app"
    )
    assert "api_key" in found
    assert "jwt" in found
    assert "database_url" in found


def test_apg_tool_identifier_not_entropy_secret() -> None:
    assert "high_entropy_token" not in subtypes("call apg_openai_connectivity_check")


def test_email_detected() -> None:
    assert "email" in subtypes("email howard@example.com")


def test_local_path_detected() -> None:
    assert "local_path" in subtypes("/Users/howard/private/project/.env")


def test_ssh_private_key_block_detected() -> None:
    text = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
    assert "private_key" in subtypes(text)


def test_jwt_detected() -> None:
    text = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    assert "jwt" in subtypes(text)


def test_credit_card_luhn() -> None:
    assert luhn_valid("4111 1111 1111 1111")
    assert "credit_card" in subtypes("card 4111 1111 1111 1111")


def test_normal_api_route_not_local_path() -> None:
    assert "local_path" not in subtypes("GET /api/v1/users returns JSON")
