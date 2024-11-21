import pytest
from cvss.services.cvss_service import CVSSService

@pytest.fixture
def cvss_service():
    return CVSSService()

def test_validate_metrics_valid(cvss_service):
    """Test metric validation with valid metrics."""
    metrics = {
        'AV': 'N',
        'AC': 'L',
        'PR': 'N',
        'UI': 'N',
        'S': 'U',
        'C': 'H',
        'I': 'H',
        'A': 'H'
    }
    assert cvss_service._validate_metrics(metrics) is True

def test_validate_metrics_invalid(cvss_service):
    """Test metric validation with invalid metrics."""
    metrics = {
        'AV': 'INVALID',
        'AC': 'L',
        'PR': 'N',
        'UI': 'N',
        'S': 'U',
        'C': 'H',
        'I': 'H',
        'A': 'H'
    }
    assert cvss_service._validate_metrics(metrics) is False

def test_calculate_score_critical(cvss_service):
    """Test CVSS score calculation for critical severity."""
    metrics = {
        'AV': 'N',
        'AC': 'L',
        'PR': 'N',
        'UI': 'N',
        'S': 'C',
        'C': 'H',
        'I': 'H',
        'A': 'H'
    }
    score, severity = cvss_service.calculate_score(metrics)
    assert score >= 9.0
    assert severity == "CRITICAL"

def test_calculate_score_high(cvss_service):
    """Test CVSS score calculation for high severity."""
    metrics = {
        'AV': 'N',
        'AC': 'H',
        'PR': 'N',
        'UI': 'R',
        'S': 'U',
        'C': 'H',
        'I': 'H',
        'A': 'L'
    }
    score, severity = cvss_service.calculate_score(metrics)
    assert 7.0 <= score < 9.0
    assert severity == "HIGH"

def test_calculate_score_medium(cvss_service):
    """Test CVSS score calculation for medium severity."""
    metrics = {
        'AV': 'L',
        'AC': 'H',
        'PR': 'L',
        'UI': 'R',
        'S': 'U',
        'C': 'L',
        'I': 'L',
        'A': 'N'
    }
    score, severity = cvss_service.calculate_score(metrics)
    assert 4.0 <= score < 7.0
    assert severity == "MEDIUM"

def test_calculate_score_low(cvss_service):
    """Test CVSS score calculation for low severity."""
    metrics = {
        'AV': 'P',
        'AC': 'H',
        'PR': 'H',
        'UI': 'R',
        'S': 'U',
        'C': 'L',
        'I': 'N',
        'A': 'N'
    }
    score, severity = cvss_service.calculate_score(metrics)
    assert 0.1 <= score < 4.0
    assert severity == "LOW"
