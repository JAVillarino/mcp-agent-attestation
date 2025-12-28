"""
Tests for CLI Tools

Run with: pytest tests/test_cli.py -v
"""

import json
import sys
from io import StringIO
from unittest.mock import patch

import pytest


class TestCLIKeygen:
    """Tests for keygen command."""

    def test_keygen_generates_key(self):
        """Test key generation produces valid JWK."""
        from attestation.cli import cmd_keygen
        import argparse

        args = argparse.Namespace(kid="test-key", output="json", out_file=None)

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_keygen(args)

        assert result == 0
        output = json.loads(mock_stdout.getvalue())
        assert output["kty"] == "OKP"
        assert output["crv"] == "Ed25519"
        assert output["kid"] == "test-key"
        assert "x" in output

    def test_keygen_auto_kid(self):
        """Test key generation with auto-generated kid."""
        from attestation.cli import cmd_keygen
        import argparse

        args = argparse.Namespace(kid=None, output="json", out_file=None)

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_keygen(args)

        assert result == 0
        output = json.loads(mock_stdout.getvalue())
        assert output["kid"].startswith("key-")


class TestCLIGenerate:
    """Tests for generate command."""

    def test_generate_token(self):
        """Test token generation."""
        from attestation.cli import cmd_generate
        import argparse

        args = argparse.Namespace(
            issuer="https://api.anthropic.com",
            audience="https://server.com",
            model_family="claude-4",
            model_version="claude-sonnet-4",
            provider_name="anthropic",
            deployment_id=None,
            lifetime=300,
            safety_level="standard",
            capabilities=None,
            system_prompt=None,
            kid=None,
            key_file=None,
            output="token",
        )

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_generate(args)

        assert result == 0
        token = mock_stdout.getvalue().strip()
        assert token.count(".") == 2  # JWT format

    def test_generate_token_json_output(self):
        """Test token generation with JSON output."""
        from attestation.cli import cmd_generate
        import argparse

        args = argparse.Namespace(
            issuer="https://api.anthropic.com",
            audience="https://server.com",
            model_family="claude-4",
            model_version="claude-sonnet-4",
            provider_name="anthropic",
            deployment_id=None,
            lifetime=300,
            safety_level="standard",
            capabilities="tool_use,code",
            system_prompt=None,
            kid="my-key",
            key_file=None,
            output="json",
        )

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_generate(args)

        assert result == 0
        output = json.loads(mock_stdout.getvalue())
        assert "token" in output
        assert "decoded" in output
        assert "public_key" in output
        assert output["public_key"]["kid"] == "my-key"


class TestCLIInspect:
    """Tests for inspect command."""

    def test_inspect_token(self):
        """Test token inspection."""
        from attestation.cli import cmd_inspect, cmd_generate
        import argparse

        # First generate a token
        gen_args = argparse.Namespace(
            issuer="https://api.anthropic.com",
            audience="https://server.com",
            model_family="claude-4",
            model_version="claude-sonnet-4",
            provider_name="anthropic",
            deployment_id=None,
            lifetime=300,
            safety_level="standard",
            capabilities=None,
            system_prompt=None,
            kid=None,
            key_file=None,
            output="token",
        )

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            cmd_generate(gen_args)
        token = mock_stdout.getvalue().strip()

        # Now inspect it
        inspect_args = argparse.Namespace(token=token, output="json")

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_inspect(inspect_args)

        assert result == 0
        output = json.loads(mock_stdout.getvalue())
        assert "header" in output
        assert "payload" in output
        assert output["payload"]["iss"] == "https://api.anthropic.com"
        assert output["payload"]["aud"] == "https://server.com"

    def test_inspect_invalid_token(self):
        """Test inspection of invalid token."""
        from attestation.cli import cmd_inspect
        import argparse

        args = argparse.Namespace(token="not.a.valid.jwt", output="text")

        with patch("sys.stderr", new_callable=StringIO):
            result = cmd_inspect(args)

        assert result == 1


class TestDecodeJWT:
    """Tests for JWT decoding utility."""

    def test_decode_jwt_unsafe(self):
        """Test JWT decoding without verification."""
        from attestation.cli import decode_jwt_unsafe

        # Create a simple JWT manually
        import base64

        header = base64.urlsafe_b64encode(
            b'{"alg":"EdDSA","typ":"JWT"}'
        ).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(
            b'{"iss":"test","sub":"subject"}'
        ).decode().rstrip("=")
        signature = base64.urlsafe_b64encode(b"sig").decode().rstrip("=")

        token = f"{header}.{payload}.{signature}"
        decoded = decode_jwt_unsafe(token)

        assert decoded["header"]["alg"] == "EdDSA"
        assert decoded["payload"]["iss"] == "test"

    def test_decode_jwt_invalid_format(self):
        """Test decoding invalid JWT format."""
        from attestation.cli import decode_jwt_unsafe

        with pytest.raises(ValueError, match="Invalid JWT format"):
            decode_jwt_unsafe("not-a-jwt")


class TestCLIMain:
    """Tests for main CLI entry point."""

    def test_main_no_command(self):
        """Test main with no command shows help."""
        from attestation.cli import main

        with patch("sys.argv", ["attestation"]):
            with patch("sys.stdout", new_callable=StringIO):
                result = main()

        assert result == 1

    def test_main_keygen(self):
        """Test main with keygen command."""
        from attestation.cli import main

        with patch("sys.argv", ["attestation", "keygen", "--kid", "test"]):
            with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
                result = main()

        assert result == 0
        assert "test" in mock_stdout.getvalue()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
