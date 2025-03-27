# nightcrawler/passive_scanner.py
from mitmproxy import http, ctx
from typing import Dict  # For type hint


# Main function called by the addon
def run_all_passive_checks(flow: http.HTTPFlow):
    """Executes all defined passive checks on the response."""
    # ctx.log.debug(f"[Passive Check] Running for {flow.request.pretty_url}") # Uncomment for verbose logging
    _check_security_headers(flow.response.headers, flow.request.pretty_url)
    _check_cookie_attributes(flow.response.cookies, flow.request.pretty_url)
    _check_info_disclosure(flow.response.text, flow.request.pretty_url)
    # Add calls to other passive check functions here...


# "Private" functions for individual checks
def _check_security_headers(headers: Dict[str, str], url: str):
    """Checks for the presence of common security headers."""
    missing = []
    # Basic examples - expand with newer headers (Permissions-Policy, COOP, COEP etc.)
    if "Strict-Transport-Security" not in headers:
        missing.append("Strict-Transport-Security")
    if (
        "Content-Security-Policy" not in headers
        and "Content-Security-Policy-Report-Only" not in headers
    ):
        missing.append("Content-Security-Policy")
    if "X-Content-Type-Options" not in headers:
        missing.append("X-Content-Type-Options")
    if "X-Frame-Options" not in headers:
        missing.append("X-Frame-Options")
    if "Referrer-Policy" not in headers:
        missing.append("Referrer-Policy")

    if missing:
        ctx.log.warn(f"[Passive Scan] Missing Headers: {', '.join(missing)} at {url}")


def _check_cookie_attributes(cookies: Dict[str, http.Cookie], url: str):
    """Checks Secure, HttpOnly, and SameSite attributes for Set-Cookie headers."""
    # Cookie parsing can be complex; this is a simplified example looking at raw headers
    set_cookie_headers = cookies.get_all("Set-Cookie")
    for header_value in set_cookie_headers:
        issues = []
        header_lower = header_value.lower()
        # Basic parsing for the name
        cookie_name = header_value.split("=", 1)[0].strip()

        # Check for Secure flag (especially important for HTTPS sites)
        if "; secure" not in header_lower:
            if url.startswith("https://"):
                issues.append("Missing Secure flag")
        # Check for HttpOnly flag
        if "; httponly" not in header_lower:
            issues.append("Missing HttpOnly flag")
        # Check for SameSite attribute presence
        if "samesite=" not in header_lower:
            issues.append("Missing SameSite attribute")
        # More specific check for invalid SameSite=None without Secure
        elif "samesite=none" in header_lower and "; secure" not in header_lower:
            issues.append("SameSite=None requires Secure flag")

        if issues:
            # Use repr() for the name in case it contains unusual characters
            ctx.log.warn(
                f"[Passive Scan] Cookie {cookie_name!r} issues: {', '.join(issues)} at {url}"
            )


def _check_info_disclosure(response_text: str | None, url: str):
    """Checks for comments or potential keywords in the response body."""
    if not response_text:
        return

    # Example: Find HTML/JS comments (requires import re)
    # import re
    # comments = re.findall(r"|/\*.*?\*/|//.*", response_text, re.DOTALL)
    # if comments:
    #     ctx.log.info(f"[Passive Scan] Found HTML/JS comments at {url}")

    # Example: Search for potential keywords (HIGH RISK OF FALSE POSITIVES)
    # Use with extreme caution, needs much more refined regex or logic.
    # import re
    # potential_keys = re.findall(r'\b(key|token|secret|password|pwd|api|auth)\b', response_text, re.IGNORECASE)
    # if potential_keys:
    #      ctx.log.warn(f"[Passive Scan] Potential sensitive keyword found in response body at {url}")
    pass  # Implement more robust logic if needed
