# nightcrawler/crawler.py
# This module contains the logic for parsing HTML responses to find new URLs for crawling.

from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from mitmproxy import ctx  # For logging via mitmproxy's context
import asyncio  # For Queue type hint
from typing import Set  # For type hint

# Import the utility function for scope checking
try:
    from nightcrawler.utils import is_in_scope
except ImportError:
    # Fallback or error handling if utils is not found (should not happen in package)
    import logging

    logging.critical(
        "Could not import is_in_scope from nightcrawler.utils in crawler.py"
    )

    # Define a dummy function to avoid crashing, but log an error
    def is_in_scope(url: str, target_domains: set) -> bool:
        logging.error("is_in_scope function unavailable in crawler.py")
        return False

# Note: The actual crawl worker (_crawl_worker) remains in addon.py
# This function is called by the addon's response hook.


def parse_and_queue_links(
    html_content: str,
    base_url: str,
    discovered_urls: Set[str],  # Shared state passed from the main addon instance
    crawl_queue: asyncio.Queue,  # Shared state passed from the main addon instance
    target_domains: Set[
        str
    ],  # The effective scope set, passed from the main addon instance
):
    """
    Parses HTML content to find links (<a>, <script>, <img>, <link>, <form>, etc.).
    Adds new, in-scope, absolute URLs to the crawl queue and the discovered set.

    Args:
        html_content: The HTML content string to parse.
        base_url: The URL of the page from which the HTML content was obtained, used to resolve relative links.
        discovered_urls: A set containing all URLs discovered so far (shared state).
        crawl_queue: An asyncio Queue to which new URLs for crawling should be added (shared state).
        target_domains: A set of domain strings defining the crawling/scanning scope.
    """
    new_links_found = 0
    ctx.log.debug(f"[Crawler Parse] Starting HTML parsing for {base_url}")
    try:
        # Using 'html.parser' (built-in). 'lxml' is faster if installed, but adds a dependency.
        soup = BeautifulSoup(html_content, "html.parser")

        # Find tags that commonly contain links or resource references
        tags_with_links = (
            soup.find_all(
                ["a", "link", "iframe", "frame"],
                href=True,  # Links, stylesheets, frames
            )
            + soup.find_all(
                [
                    "script",
                    "img",
                    "iframe",
                    "frame",
                    "audio",
                    "video",
                    "embed",
                    "source",
                ],
                src=True,  # Scripts, media, frames
            )
            + soup.find_all(
                "form",
                action=True,  # Form submission targets
            )
        )
        # Could also consider 'object[data]', 'applet[code]', etc. if needed

        for tag in tags_with_links:
            # Determine the attribute containing the link/URL
            if tag.name == "form":
                link = tag.get("action")
            elif tag.has_attr("href"):
                link = tag["href"]
            elif tag.has_attr("src"):
                link = tag["src"]
            else:
                continue  # Should not happen based on find_all query

            if not link:
                continue  # Skip empty attributes (e.g., action="")

            link_str = link.strip()

            # Basic filter for non-web schemes (javascript:, mailto:, data:, etc.)
            # Allows relative paths (/, ?, #) and http/https
            if ":" in link_str and not link_str.lower().startswith(
                ("http", "/", "#", "?")
            ):
                # ctx.log.debug(f"[Crawler Parse] Skipping special scheme link: {link_str[:50]}...") # Can be very verbose
                continue

            # Resolve the link to an absolute URL based on the page's base URL
            try:
                absolute_url = urljoin(base_url, link_str)
            except ValueError:
                ctx.log.debug(
                    f"[Crawler Parse] Skipping invalid URL derived from '{link_str}'"
                )
                continue

            # Clean the URL: remove fragment (#section) as it's client-side
            try:
                parsed_uri = urlparse(absolute_url)
                # Only proceed if scheme is http or https
                if parsed_uri.scheme not in ["http", "https"]:
                    continue
                absolute_url = parsed_uri._replace(fragment="").geturl()
            except ValueError:
                ctx.log.debug(
                    f"[Crawler Parse] Skipping malformed absolute URL: {absolute_url}"
                )
                continue

            # Avoid re-adding the page's own URL or URLs with no path component
            if absolute_url == base_url or not urlparse(absolute_url).path:
                continue

            # --- Scope and Duplicate Check ---
            # Use the utility function imported from utils.py, passing the effective scope
            if (
                is_in_scope(absolute_url, target_domains)
                and absolute_url not in discovered_urls
            ):
                # If it's in scope and we haven't seen it before:
                discovered_urls.add(absolute_url)  # Add to the master set
                crawl_queue.put_nowait(absolute_url)  # Add to the queue for the worker
                new_links_found += 1
                # Log every discovered URL at INFO level
                ctx.log.info(f"[CRAWLER DISCOVERY] Found new URL: {absolute_url}")

        # Log summary after parsing the whole page if new links were found
        if new_links_found > 0:
            ctx.log.debug(
                f"[Crawler Parse] Added {new_links_found} new unique URLs to crawl queue from {base_url}. Queue size now: {crawl_queue.qsize()}"
            )
        else:
            ctx.log.debug(f"[Crawler Parse] No new URLs found in scope from {base_url}")

    except Exception as e:
        # Log exceptions during parsing, potentially including traceback for debugging
        # import traceback
        # ctx.log.error(f"[CRAWLER] Error parsing HTML from {base_url}: {e}\n{traceback.format_exc()}")
        ctx.log.warn(f"[CRAWLER] Error parsing HTML from {base_url}: {e}")


# Example of how this function is called from addon.py's response hook:
# parse_and_queue_links(
#     flow.response.text,
#     flow.request.pretty_url,
#     self.discovered_urls, # The addon's state set
#     self.crawl_queue,     # The addon's state queue
#     self.effective_scope  # The addon's processed scope set
# )

