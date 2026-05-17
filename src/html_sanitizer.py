"""
src/html_sanitizer.py
=====================
Sanitise untrusted strings before embedding them in WeasyPrint-generated HTML.

Problem: pdf_export.py inserts `proof` (fuzzer output), `description`, and
         `title` from VulnerabilityModel directly into an HTML template.
         If those fields contain '<script>alert(1)</script>' or similar,
         they could be rendered unsafely if the PDF is viewed in a browser.

Solution: This module provides three sanitization levels:
  1. sanitise_text       — allows safe formatting tags (<code>, <pre>, <b>)
  2. sanitise_url        — blocks javascript: and data: URIs
  3. sanitise_curl_poc   — full escape (no tags) for PoC blocks

Usage:
    from src.html_sanitizer import sanitise_text, sanitise_url, sanitise_curl_poc

    title = sanitise_text(vuln.title, max_length=200)
    desc = sanitise_text(vuln.description, max_length=1000)
    proof = sanitise_curl_poc(vuln.proof)
    url = sanitise_url(vuln.url)
"""

import html
import re
from typing import Optional

# Maximum field length to bound processing time (DoS protection)
_MAX_FIELD_LENGTH = 10000

# Whitelist of safe HTML tags (no attributes allowed)
# These tags are purely for formatting and cannot execute code
_SAFE_TAGS = frozenset({"code", "pre", "b", "i", "strong", "em", "br", "span"})

# Regex to detect javascript: protocol (case-insensitive, with optional whitespace)
_JS_PROTO_RE = re.compile(r"^\s*javascript\s*:", re.IGNORECASE)


def sanitise_text(value: Optional[str], max_length: int = _MAX_FIELD_LENGTH) -> str:
    """
    Sanitise text for embedding in HTML, allowing whitelisted formatting tags.

    Process:
      1. HTML-encode the entire string (< becomes &lt;, etc.)
      2. Re-allow whitelisted tags ONLY (without attributes)

    This prevents XSS while allowing safe formatting like <code>, <pre>, <b>.

    Example:
        Input:  'Use <code>function()</code> here. <script>alert(1)</script>'
        Output: 'Use <code>function()</code> here. &lt;script&gt;alert(1)&lt;/script&gt;'

    Example (with curl):
        curl -s 'https://example.com?q=<script>alert(1)</script>'
    becomes:
        curl -s 'https://example.com?q=&lt;script&gt;alert(1)&lt;/script&gt;'
    which renders visibly in the PDF but does not execute.

    Parameters
    ----------
    value : str or None
        The text to sanitise
    max_length : int
        Maximum length before truncation (default 10000)

    Returns
    -------
    str
        Sanitised HTML-safe string with whitelisted tags restored
    """
    if value is None:
        return ""

    # Truncate early to bound processing time
    value = str(value)[:max_length]

    # Step 1: HTML-encode the entire string
    escaped = html.escape(value, quote=True)

    # Step 2: Re-allow whitelisted tags (without attributes)
    # We look for patterns like &lt;code&gt; and turn them back into <code>
    def _restore_safe_tag(m: re.Match) -> str:
        tag = m.group(2).lower()
        closing = m.group(1)  # "/" if closing tag, empty if opening
        if tag in _SAFE_TAGS:
            return f"<{closing}{tag}>"
        # Keep escaped for unsafe tags
        return m.group(0)

    safe = re.sub(
        r"&lt;(/?)(\w+)&gt;",
        _restore_safe_tag,
        escaped,
        flags=re.IGNORECASE,
    )

    return safe


def sanitise_url(url: Optional[str]) -> str:
    """
    Return a safe URL string for use in href/src attributes.

    Blocks javascript: and data: URIs; escapes HTML entities.

    This prevents Protocol Smuggling attacks where malicious URLs
    can execute JavaScript or embed dangerous content.

    Examples:
        javascript:alert(1)           → #
        data:text/html,<script>...    → #
        https://safe.com              → https://safe.com (escaped)

    Parameters
    ----------
    url : str or None
        The URL to sanitise

    Returns
    -------
    str
        Safe URL or "#" if dangerous protocol detected
    """
    if not url:
        return "#"

    url = str(url).strip()

    # Block javascript: protocol (case-insensitive, with optional whitespace)
    if _JS_PROTO_RE.match(url):
        return "#"

    # Block data: protocol (can contain embedded HTML/JS)
    if re.match(r"data\s*:", url, re.IGNORECASE):
        return "#"

    # Escape HTML entities in the URL
    return html.escape(url, quote=True)


def sanitise_curl_poc(proof: Optional[str]) -> str:
    """
    Specialised sanitiser for curl PoC blocks in PDF reports.

    Wraps content in <pre><code> and escapes everything.
    The PoC is display-only; no re-allowed tags.

    This ensures that even if the fuzzer produces output with HTML tags,
    they will be displayed as text rather than executed.

    Example:
        Input:  curl 'https://target.com?param=<img src=x onerror="alert(1)">'
        Output: <pre><code>curl 'https://target.com?param=&lt;img src=x onerror=&quot;alert(1)&quot;&gt;'</code></pre>

    Parameters
    ----------
    proof : str or None
        The PoC/proof text (usually curl command)

    Returns
    -------
    str
        HTML-safe PoC wrapped in <pre><code> tags
    """
    if not proof:
        return "<pre><code>(no proof available)</code></pre>"

    # Full HTML escape with length limit
    escaped = html.escape(str(proof)[:_MAX_FIELD_LENGTH], quote=True)

    # Wrap in pre/code for monospace display
    return f"<pre><code>{escaped}</code></pre>"


def sanitise_snippet(snippet: Optional[str], max_length: int = 500) -> str:
    """
    Sanitise code snippets (reproduction commands in multiple languages).

    Similar to sanitise_curl_poc but without the wrapping tags,
    since the caller may want to apply their own formatting.

    Parameters
    ----------
    snippet : str or None
        Code snippet to sanitise
    max_length : int
        Maximum length before truncation

    Returns
    -------
    str
        HTML-safe snippet text
    """
    if not snippet:
        return "(no snippet available)"

    return html.escape(str(snippet)[:max_length], quote=True)


# Convenience function for backwards compatibility with old _escape()
def escape_basic(value: Optional[str]) -> str:
    """
    Basic HTML escape for simple values.

    This is a drop-in replacement for the old _escape() function.
    Use sanitise_text() instead if you want to allow formatting tags.

    Parameters
    ----------
    value : str or None
        Value to escape

    Returns
    -------
    str
        HTML-escaped string
    """
    return html.escape(str(value) if value is not None else "", quote=True)
