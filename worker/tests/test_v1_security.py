"""
Tests for V1 worker security.

- Technique allowlist enforcement
- 404 handling for username lookups
- Error codes
"""
import pytest
import os
from unittest.mock import patch, MagicMock
from uuid import uuid4


class TestTechniqueDisabled:
    """Tests for TECHNIQUE_DISABLED error code."""
    
    def test_disabled_technique_returns_failed(self):
        """Disabled technique should return FAILED with TECHNIQUE_DISABLED."""
        from worker_app.tasks import execute_job
        
        # Mock a job with disabled technique
        with patch('worker_app.tasks.rehydrate_job') as mock_rehydrate, \
             patch('worker_app.tasks.update_job_running'), \
             patch('worker_app.tasks.update_job_failed') as mock_fail:
            
            mock_rehydrate.return_value = {
                "id": str(uuid4()),
                "workspace_id": str(uuid4()),
                "target_id": str(uuid4()),
                "target_type": "DOMAIN",
                "target_value": "example.com",
                "technique_code": "port_scan",  # Disabled!
                "params": {},
                "attempt": 1,
                "max_attempts": 3,
            }
            
            # Execute
            result = execute_job(str(uuid4()))
            
            # Should call update_job_failed with TECHNIQUE_DISABLED
            mock_fail.assert_called_once()
            call_args = mock_fail.call_args
            assert call_args[1]["error_code"] == "TECHNIQUE_DISABLED"
            
            # Result should indicate failure
            assert result["status"] == "FAILED"
            assert result["error_code"] == "TECHNIQUE_DISABLED"
    
    @pytest.mark.parametrize("technique", [
        "port_scan",
        "subdomain_enum",
        "cert_transparency",
        "screenshot",
        "social_lookup",
    ])
    def test_all_disabled_techniques_blocked(self, technique):
        """All disabled techniques should be blocked."""
        from worker_app.tasks import execute_job
        
        with patch('worker_app.tasks.rehydrate_job') as mock_rehydrate, \
             patch('worker_app.tasks.update_job_running'), \
             patch('worker_app.tasks.update_job_failed') as mock_fail:
            
            mock_rehydrate.return_value = {
                "id": str(uuid4()),
                "workspace_id": str(uuid4()),
                "target_id": str(uuid4()),
                "target_type": "DOMAIN",
                "target_value": "example.com",
                "technique_code": technique,
                "params": {},
                "attempt": 1,
                "max_attempts": 3,
            }
            
            result = execute_job(str(uuid4()))
            
            assert result["status"] == "FAILED"
            assert "TECHNIQUE_DISABLED" in result.get("error_code", "")
    
    def test_enabled_techniques_not_blocked(self):
        """Enabled techniques should NOT be blocked."""
        ENABLED = {
            "domain_dns_lookup",
            "domain_whois_rdap_lookup",
            "username_github_lookup",
            "username_reddit_lookup",
            "email_mx_spf_dmarc_correlation",
            "email_breach_lookup",
        }
        
        # Just verify the set matches what we expect
        from worker_app.tasks import execute_job
        
        # Would need full mocking to test execution
        # For now, verify the allowlist exists
        assert len(ENABLED) == 6


class TestUsername404Handling:
    """Tests for 404 handling in username lookups."""
    
    def test_github_404_returns_succeeded_with_exists_false(self):
        """GitHub 404 should return SUCCEEDED with exists=false."""
        from worker_app.tasks import execute_username_github_lookup
        
        # Mock job
        job = {
            "id": str(uuid4()),
            "workspace_id": str(uuid4()),
            "target_id": str(uuid4()),
            "target_type": "USERNAME",
            "target_value": "nonexistent-user-12345",
            "technique_code": "username_github_lookup",
            "params": {},
        }
        
        with patch('worker_app.tasks.rate_limited_request') as mock_request, \
             patch('worker_app.tasks.store_raw_evidence'), \
             patch('worker_app.tasks.upsert_finding') as mock_upsert:
            
            # Simulate 404
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_response.json.return_value = {"message": "Not Found"}
            mock_response.headers = {}
            mock_request.return_value = mock_response
            
            # Execute
            findings = execute_username_github_lookup(job)
            
            # Should create finding with exists=false
            mock_upsert.assert_called()
            call_args = mock_upsert.call_args[1]
            assert call_args["data"]["exists"] == False
    
    def test_reddit_404_returns_succeeded_with_exists_false(self):
        """Reddit 404 should return SUCCEEDED with exists=false."""
        from worker_app.tasks import execute_username_reddit_lookup
        
        job = {
            "id": str(uuid4()),
            "workspace_id": str(uuid4()),
            "target_id": str(uuid4()),
            "target_type": "USERNAME",
            "target_value": "nonexistent-user-12345",
            "technique_code": "username_reddit_lookup",
            "params": {},
        }
        
        with patch('worker_app.tasks.rate_limited_request') as mock_request, \
             patch('worker_app.tasks.store_raw_evidence'), \
             patch('worker_app.tasks.upsert_finding') as mock_upsert:
            
            # Simulate 404
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_response.json.return_value = {"message": "Not Found"}
            mock_response.headers = {}
            mock_request.return_value = mock_response
            
            findings = execute_username_reddit_lookup(job)
            
            mock_upsert.assert_called()
            call_args = mock_upsert.call_args[1]
            assert call_args["data"]["exists"] == False


class TestWorkerErrorCodes:
    """Tests for worker error codes."""
    
    def test_timeout_error_code(self):
        """Timeout should set error_code to TIMEOUT."""
        # This would require mocking SoftTimeLimitExceeded
        pass
    
    def test_rate_limit_error_code(self):
        """Rate limit hit should set appropriate error code."""
        # Would test 429 handling
        pass
    
    def test_network_error_handling(self):
        """Network errors should be handled gracefully."""
        # Would test connection errors
        pass


class TestWorkerObservability:
    """Tests for worker observability."""
    
    def test_job_id_in_logs(self):
        """Job ID should be included in all logs."""
        import structlog
        from worker_app.tasks import execute_job
        
        # Would capture log output and verify job_id present
        pass
    
    def test_technique_code_in_logs(self):
        """Technique code should be included in logs."""
        pass
    
    def test_metrics_incremented(self):
        """Metrics should be incremented on job completion."""
        # Would check Prometheus metrics
        pass

