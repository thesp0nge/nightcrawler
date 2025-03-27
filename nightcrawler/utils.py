# nightcrawler/utils.py
from urllib.parse import urlparse
from mitmproxy import http
from typing import Optional, Set  # Updated type hint


def is_in_scope(url: str, target_domains: Set[str]) -> bool:
    """Checks if the given URL is within the defined scope."""
    if not url or not target_domains:
        return False
    try:
        domain = urlparse(url).netloc
        # Check if the URL's domain exactly matches or ends with one of the target domains
        # This correctly handles subdomains (e.g., "sub.example.com" matches "example.com")
        return any(
            domain == scope_domain or domain.endswith(f".{scope_domain}")
            for scope_domain in target_domains
            if scope_domain
        )
    except Exception:
        # Consider malformed URLs as out of scope
        return False


def create_target_signature(request: http.Request) -> Optional[str]:
    """
    Creates a unique signature for a potential scan target
    (URL path + parameter names). Used for deduplication.
    Returns None if no parameters are found.
    """
    parsed_url = urlparse(request.pretty_url)
    base_url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path

    # Collect parameter names from GET query and urlencoded POST body
    param_names = set(request.query.keys())
    if request.method == "POST" and request.urlencoded_form:
        param_names.update(request.urlencoded_form.keys())
    # TODO: In the future, consider JSON body keys, XML, etc.

    # If no parameters are identified, don't generate a scan signature
    if not param_names:
        return None

    # Sort names to make the signature consistent regardless of original order
    signature = f"{request.method}::{base_url}::{','.join(sorted(list(param_names)))}"
    return signature
