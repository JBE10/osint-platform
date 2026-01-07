"""
Pytest configuration and fixtures.
"""
import pytest


def pytest_configure(config):
    """Configure custom markers."""
    config.addinivalue_line(
        "markers", "integration: mark test as integration test (requires network)"
    )


@pytest.fixture
def sample_spf_records():
    """Sample SPF records for testing."""
    return [
        "v=spf1 include:_spf.google.com ~all",
        "v=spf1 ip4:192.168.1.0/24 -all",
        "v=spf1 a mx include:spf.protection.outlook.com ~all",
        "v=spf1 ?all",
    ]


@pytest.fixture
def sample_dmarc_records():
    """Sample DMARC records for testing."""
    return [
        "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
        "v=DMARC1; p=reject; pct=100",
        "v=DMARC1; p=quarantine; sp=reject; pct=50; rua=mailto:a@x.com,mailto:b@y.com",
    ]


@pytest.fixture
def mock_dns_response():
    """Mock DNS response for testing."""
    return {
        "domain": "example.com",
        "records": {
            "A": [{"value": "93.184.216.34", "ttl": 3600}],
            "AAAA": [{"value": "2606:2800:220:1:248:1893:25c8:1946", "ttl": 3600}],
            "MX": [{"exchange": "mail.example.com", "priority": 10, "ttl": 3600}],
            "NS": [{"value": "a.iana-servers.net", "ttl": 86400}],
            "TXT": [
                {"value": "v=spf1 -all", "ttl": 3600},
            ],
        },
        "resolver": "system",
        "queried_at": "2026-01-06T12:00:00Z",
    }


@pytest.fixture
def mock_rdap_response():
    """Mock RDAP response for testing."""
    return {
        "objectClassName": "domain",
        "handle": "2336799_DOMAIN_COM-VRSN",
        "ldhName": "EXAMPLE.COM",
        "links": [],
        "status": ["clientDeleteProhibited", "clientTransferProhibited"],
        "entities": [
            {
                "objectClassName": "entity",
                "handle": "376",
                "roles": ["registrar"],
                "publicIds": [{"type": "IANA Registrar ID", "identifier": "376"}],
                "vcardArray": [
                    "vcard",
                    [["version", {}, "text", "4.0"], ["fn", {}, "text", "ICANN"]],
                ],
            }
        ],
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2024-08-13T04:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2023-08-14T07:01:38Z"},
        ],
        "nameservers": [
            {"objectClassName": "nameserver", "ldhName": "A.IANA-SERVERS.NET"},
            {"objectClassName": "nameserver", "ldhName": "B.IANA-SERVERS.NET"},
        ],
    }

