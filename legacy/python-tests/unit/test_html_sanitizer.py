"""
tests/unit/test_html_sanitizer.py
==================================
Unit tests for HTML sanitization module.

Run with: pytest tests/unit/test_html_sanitizer.py -v
"""

from src.html_sanitizer import (
    sanitise_text,
    sanitise_url,
    sanitise_curl_poc,
    sanitise_snippet,
    escape_basic,
)


class TestSanitiseText:
    """Tests for sanitise_text function."""

    def test_allows_safe_tags(self):
        """Should allow whitelisted formatting tags."""
        input_text = "Use <code>function()</code> and <pre>block</pre>"
        output = sanitise_text(input_text)
        assert "<code>function()</code>" in output
        assert "<pre>block</pre>" in output

    def test_blocks_script_tags(self):
        """Should escape <script> tags."""
        input_text = "<script>alert(1)</script>"
        output = sanitise_text(input_text)
        assert "<script>" not in output
        assert "&lt;script&gt;" in output
        assert "&lt;/script&gt;" in output

    def test_blocks_img_tags(self):
        """Should escape <img> tags."""
        input_text = '<img src=x onerror="alert(1)">'
        output = sanitise_text(input_text)
        assert "<img" not in output
        assert "&lt;img" in output

    def test_allows_nested_safe_tags(self):
        """Should allow nested whitelisted tags."""
        input_text = "<pre><code>nested content</code></pre>"
        output = sanitise_text(input_text)
        assert "<pre><code>nested content</code></pre>" == output

    def test_mixed_safe_and_unsafe(self):
        """Should allow safe tags but escape unsafe ones."""
        input_text = '<b>bold</b> <script>bad</script> <code>good</code>'
        output = sanitise_text(input_text)
        assert "<b>bold</b>" in output
        assert "<code>good</code>" in output
        assert "&lt;script&gt;" in output

    def test_handles_none_input(self):
        """Should return empty string for None input."""
        output = sanitise_text(None)
        assert output == ""

    def test_respects_max_length(self):
        """Should truncate input at max_length."""
        long_text = "A" * 1000
        output = sanitise_text(long_text, max_length=100)
        assert len(output) == 100

    def test_escapes_html_entities(self):
        """Should escape HTML entities like &, <, >."""
        input_text = "Use & to join, < for less, > for more"
        output = sanitise_text(input_text)
        assert "&amp;" in output
        assert "&lt;" in output
        assert "&gt;" in output

    def test_case_insensitive_tags(self):
        """Should handle tags in any case."""
        input_text = "<CODE>uppercase</CODE> <Pre>mixed</Pre>"
        output = sanitise_text(input_text)
        assert "<code>uppercase</code>" in output.lower()


class TestSanitiseUrl:
    """Tests for sanitise_url function."""

    def test_allows_https_urls(self):
        """Should allow and escape HTTPS URLs."""
        url = "https://example.com/path?query=value"
        output = sanitise_url(url)
        assert output == url

    def test_allows_http_urls(self):
        """Should allow and escape HTTP URLs."""
        url = "http://example.com"
        output = sanitise_url(url)
        assert output == url

    def test_blocks_javascript_protocol(self):
        """Should block javascript: URLs."""
        url = "javascript:alert(1)"
        output = sanitise_url(url)
        assert output == "#"

    def test_blocks_javascript_with_whitespace(self):
        """Should block javascript: with whitespace variations."""
        urls = [
            "  javascript:alert(1)",
            "javascript  :alert(1)",
            "\tjavascript:alert(1)",
        ]
        for url in urls:
            output = sanitise_url(url)
            assert output == "#", f"Failed for: {url}"

    def test_blocks_javascript_mixed_case(self):
        """Should block javascript: in any case."""
        urls = ["JavaScript:alert(1)", "JAVASCRIPT:alert(1)", "JaVaScRiPt:alert(1)"]
        for url in urls:
            output = sanitise_url(url)
            assert output == "#", f"Failed for: {url}"

    def test_blocks_data_protocol(self):
        """Should block data: URLs."""
        url = "data:text/html,<script>alert(1)</script>"
        output = sanitise_url(url)
        assert output == "#"

    def test_handles_empty_input(self):
        """Should return # for empty input."""
        assert sanitise_url("") == "#"
        assert sanitise_url(None) == "#"

    def test_escapes_html_in_urls(self):
        """Should escape HTML entities in URLs."""
        url = 'https://example.com?param=<script>alert(1)</script>'
        output = sanitise_url(url)
        assert "&lt;script&gt;" in output
        assert "<script>" not in output


class TestSanitiseCurlPoc:
    """Tests for sanitise_curl_poc function."""

    def test_wraps_in_pre_code(self):
        """Should wrap content in <pre><code> tags."""
        proof = "curl https://example.com"
        output = sanitise_curl_poc(proof)
        assert output.startswith("<pre><code>")
        assert output.endswith("</code></pre>")

    def test_escapes_all_html(self):
        """Should escape all HTML in PoC."""
        proof = 'curl "https://target.com?param=<img src=x>"'
        output = sanitise_curl_poc(proof)
        assert "&lt;img" in output
        assert "<img" not in output

    def test_handles_none_input(self):
        """Should return placeholder for None input."""
        output = sanitise_curl_poc(None)
        assert output == "<pre><code>(no proof available)</code></pre>"

    def test_handles_empty_string(self):
        """Should return placeholder for empty string."""
        output = sanitise_curl_poc("")
        assert output == "<pre><code>(no proof available)</code></pre>"

    def test_escapes_quotes(self):
        """Should escape quote characters."""
        proof = '''curl -d '{"key":"value"}' '''
        output = sanitise_curl_poc(proof)
        assert "&quot;" in output


class TestSanitiseSnippet:
    """Tests for sanitise_snippet function."""

    def test_escapes_all_html(self):
        """Should escape all HTML in snippet."""
        snippet = '<script>alert("xss")</script>'
        output = sanitise_snippet(snippet)
        assert "&lt;script&gt;" in output
        assert "<script>" not in output

    def test_respects_max_length(self):
        """Should truncate at specified max_length."""
        snippet = "A" * 1000
        output = sanitise_snippet(snippet, max_length=100)
        assert len(output) == 100

    def test_handles_none_input(self):
        """Should return placeholder for None."""
        output = sanitise_snippet(None)
        assert output == "(no snippet available)"

    def test_handles_empty_input(self):
        """Should return placeholder for empty string."""
        output = sanitise_snippet("")
        assert output == "(no snippet available)"


class TestEscapeBasic:
    """Tests for escape_basic function."""

    def test_escapes_html_entities(self):
        """Should escape all HTML entities."""
        text = '<p>Test & "quotes"</p>'
        output = escape_basic(text)
        assert "&lt;p&gt;" in output
        assert "&amp;" in output
        assert "&quot;" in output

    def test_handles_none_input(self):
        """Should return empty string for None."""
        output = escape_basic(None)
        assert output == ""

    def test_converts_to_string(self):
        """Should convert non-string types to string first."""
        output = escape_basic(123)
        assert output == "123"


class TestSecurityScenarios:
    """Tests for real-world XSS attack scenarios."""

    def test_xss_in_curl_command(self):
        """Should prevent XSS in curl PoC block."""
        malicious_poc = '''curl -s 'https://example.com?q=<script>alert(1)</script>\'
curl -d '{"xss":"<img src=x onerror=alert(1)>"}' '''
        output = sanitise_curl_poc(malicious_poc)
        assert "<script>" not in output
        assert "<img" not in output
        assert "&lt;script&gt;" in output

    def test_protocol_smuggling(self):
        """Should prevent protocol smuggling attacks."""
        urls = [
            "javascript:alert(document.domain)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "  javascript  :  alert(1)",
        ]
        for url in urls:
            output = sanitise_url(url)
            assert output == "#", f"Failed to block: {url}"

    def test_attribute_injection(self):
        """Should prevent attribute injection in text."""
        malicious_text = '<code onclick="alert(1)">click me</code>'
        output = sanitise_text(malicious_text)
        # Should keep <code> tag but remove onclick attribute
        assert "<code>" in output
        assert "onclick" not in output.lower() or "&quot;" in output

    def test_nested_encoding(self):
        """Should handle nested HTML encoding."""
        text = "&lt;script&gt;alert(1)&lt;/script&gt;"
        output = sanitise_text(text)
        # Should double-encode to prevent interpretation
        assert "&amp;lt;" in output or "&lt;script&gt;" in output


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_very_long_input(self):
        """Should handle very long inputs without errors."""
        long_text = "<script>" + ("A" * 100000) + "</script>"
        output = sanitise_text(long_text, max_length=10000)
        assert len(output) <= 10000

    def test_unicode_characters(self):
        """Should handle Unicode characters correctly."""
        text = "<code>שלום עולם 🚀</code>"
        output = sanitise_text(text)
        assert "שלום עולם 🚀" in output
        assert "<code>" in output

    def test_malformed_html(self):
        """Should handle malformed HTML gracefully."""
        text = "<code>unclosed tag"
        output = sanitise_text(text)
        assert "<code>unclosed tag" == output

    def test_empty_tags(self):
        """Should handle empty tags."""
        text = "<code></code>"
        output = sanitise_text(text)
        assert "<code></code>" == output

    def test_only_whitespace(self):
        """Should handle whitespace-only input."""
        text = "   \n\t  "
        output = sanitise_text(text)
        assert output == text
