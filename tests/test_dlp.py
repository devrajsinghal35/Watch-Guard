from backend.dlp_engine import DLPEngine

def test_dlp_ssn_detection():
    dlp = DLPEngine()
    payload = "Confidential record: user SSN is 123-45-6789 in plain text."
    violations = dlp.scan_payload(payload)

    assert len(violations) >= 1
    match = next((v for v in violations if v["category"] == "SSN"), None)
    assert match is not None
    assert match["redacted_match"] == "XXX-XX-6789"

def test_dlp_credit_card_detection():
    dlp = DLPEngine()
    payload = "Payment details: 4111111111111111 exp 12/28"
    violations = dlp.scan_payload(payload)

    assert len(violations) >= 1
    match = next((v for v in violations if v["category"] == "CREDIT_CARD"), None)
    assert match is not None
    assert match["redacted_match"] == "XXXX-XXXX-XXXX-1111"

def test_dlp_api_key_detection():
    dlp = DLPEngine()
    payload = 'Authorization: Bearer abcdef1234567890abcdef1234567890'
    violations = dlp.scan_payload(payload)

    assert len(violations) >= 1
    match = next((v for v in violations if v["category"] == "API_KEY"), None)
    assert match is not None
    assert "[REDACTED]" in match["redacted_match"]

def test_dlp_internal_header_detection():
    dlp = DLPEngine()
    payload = "GET /internal HTTP/1.1\r\nX-WatchGuard-Internal-Key: secret123"
    violations = dlp.scan_payload(payload)

    assert len(violations) >= 1
    match = next((v for v in violations if v["category"] == "INTERNAL_HEADER"), None)
    assert match is not None
    assert match["redacted_match"] == "[REDACTED_INTERNAL_DATA]"

def test_dlp_empty_payload():
    dlp = DLPEngine()
    assert dlp.scan_payload("") == []
    assert dlp.scan_payload(None) == []
