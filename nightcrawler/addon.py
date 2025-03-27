# nightcrawler/addon.py
import mitmproxy.http
from mitmproxy import ctx, http, addonmanager
import asyncio
import httpx
import time
from typing import Set, Dict, Any, Optional

# --- Imports from local package modules ---
try:
    # No longer importing TARGET_SCOPE_DOMAINS from config
    from nightcrawler.config import MAX_CONCURRENT_SCANS, USER_AGENT
    from nightcrawler.utils import is_in_scope, create_target_signature
    from nightcrawler.passive_scanner import run_all_passive_checks
    from nightcrawler.crawler import parse_and_queue_links
    from nightcrawler.sqli_scanner import scan_sqli_basic
    from nightcrawler.xss_scanner import scan_xss_basic
except ImportError as e:
    import logging

    logging.basicConfig(level=logging.CRITICAL)
    logging.critical(f"CRITICAL ERROR: Cannot import required modules.")
    logging.critical(
        f"Ensure config.py, utils.py, etc., are in the 'nightcrawler' directory."
    )
    logging.critical(f"Error details: {e}")
    raise ImportError(f"Local dependencies not found: {e}") from e


class MainAddon:
    """
    Main mitmproxy addon orchestrating proxying, passive scanning,
    crawling, and basic active scanning in the background.
    Scope is defined via the --nc-scope command-line option.
    """

    def __init__(self):
        """Initializes the addon's state."""
        self.discovered_urls: Set[str] = set()
        self.scanned_targets: Set[str] = set()
        self.scan_queue: asyncio.Queue = asyncio.Queue()
        self.crawl_queue: asyncio.Queue = asyncio.Queue()
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
        self.http_client: Optional[httpx.AsyncClient] = None
        self.crawl_worker_task: Optional[asyncio.Task] = None
        self.scan_worker_task: Optional[asyncio.Task] = None
        # Initialize effective_scope as an empty set
        self.effective_scope: Set[str] = set()
        ctx.log.info("=" * 30)
        ctx.log.info(" Main Addon v0.4 (CLI Scope) Initialized ")
        ctx.log.info("=" * 30)
        # Debug logs moved to 'configure' hook after options are processed

    def load(self, loader: addonmanager.Loader):
        """Hook called on startup to load options."""
        # Define the command-line option for the target scope
        loader.add_option(
            name="nc_scope",  # Option name accessible via ctx.options.nc_scope
            type=str,  # Expecting a string value
            default="",  # Default is an empty string (no scope)
            help="Target scope domain(s), comma-separated (e.g., example.com,sub.example.com). Required for processing.",
        )
        # Add other options here if needed

    def configure(self, updated: Set[str]):
        """Hook called when options are set or updated."""
        # Process the nc_scope option when it's set/updated
        if "nc_scope" in updated:
            scope_str = ctx.options.nc_scope
            if scope_str:
                # Split the comma-separated string, strip whitespace, filter empty strings
                self.effective_scope = {
                    s.strip() for s in scope_str.split(",") if s.strip()
                }
                ctx.log.info(
                    f"Target scope set from --nc-scope: {self.effective_scope}"
                )
            else:
                self.effective_scope = set()
                ctx.log.warn(
                    "No target scope provided via --nc-scope. Nightcrawler will not process any requests."
                )

        # Log other config values (can be done once in init or here)
        if not updated:  # Log these only once on initial configuration
            ctx.log.debug(f"Max Worker Concurrency: {MAX_CONCURRENT_SCANS}")
            ctx.log.debug(f"Scan/Crawl User Agent: {USER_AGENT}")

    def running(self):
        """Hook called when mitmproxy is ready."""
        # Initialize client and start workers (no changes here)
        if not self.http_client:
            self.http_client = httpx.AsyncClient(...)  # Same as before
        if not self.crawl_worker_task or self.crawl_worker_task.done():
            self.crawl_worker_task = asyncio.create_task(self._crawl_worker())
        if not self.scan_worker_task or self.scan_worker_task.done():
            self.scan_worker_task = asyncio.create_task(self._scan_worker())
        if not self.effective_scope:
            ctx.log.warn("REMINDER: No target scope set via --nc-scope.")
        ctx.log.info("Background workers started.")

    async def done(self):
        """Hook called on shutdown for cleanup."""
        # No changes needed here, cleanup logic remains the same
        ctx.log.info("Main Addon: Shutting down...")
        # ... (cancel tasks, close client) ...
        ctx.log.info("Main Addon: Shutdown complete.")

    # --- HTTP Hooks ---
    def request(self, flow: http.HTTPFlow) -> None:
        """Processes intercepted client requests."""
        # Check scope using the processed 'self.effective_scope' set
        if not self.effective_scope or not is_in_scope(
            flow.request.pretty_url, self.effective_scope
        ):
            return  # Ignore if no scope is set or URL is out of scope

        url = flow.request.pretty_url
        if url not in self.discovered_urls:
            self.discovered_urls.add(url)
            ctx.log.info(f"[DISCOVERY] Added URL (from Browse): {url}")

        target_signature = create_target_signature(flow.request)
        if target_signature and target_signature not in self.scanned_targets:
            self.scanned_targets.add(target_signature)
            scan_details = {...}  # Same as before
            self.scan_queue.put_nowait(scan_details)
            ctx.log.debug(
                f"[SCAN QUEUE] Add Target: {target_signature} (Qsize: {self.scan_queue.qsize()})"
            )

    def response(self, flow: http.HTTPFlow) -> None:
        """Processes intercepted server responses."""
        # Check scope using 'self.effective_scope'
        if not self.effective_scope or not is_in_scope(
            flow.request.pretty_url, self.effective_scope
        ):
            return

        # Run passive checks (no change needed here)
        run_all_passive_checks(flow)

        # Parse links for crawler, passing the effective scope
        content_type = flow.response.headers.get("Content-Type", "")
        if (
            200 <= flow.response.status_code < 300
            and "html" in content_type
            and flow.response.text
        ):
            ctx.log.debug(
                f"Response from {flow.request.pretty_url} is HTML, parsing links..."
            )
            parse_and_queue_links(
                flow.response.text,
                flow.request.pretty_url,
                self.discovered_urls,
                self.crawl_queue,
                self.effective_scope,  # Pass the processed scope set
            )

    # --- Workers (_crawl_worker, _scan_worker) ---
    # No changes needed inside the workers themselves, they use the state
    # passed during their initiation or access shared state indirectly.
    # The scope check happens *before* items are added to the queues.
    async def _crawl_worker(self):
        """Asynchronous worker that processes the crawl queue."""
        ctx.log.info("Internal Crawl Worker started.")
        while True:
            # Wait until the HTTP client is ready (initialized in 'running' hook)
            if not self.http_client:
                ctx.log.debug("[CRAWL WORKER] HTTP client not ready, waiting...")
                await asyncio.sleep(0.5)
                continue
            try:
                ctx.log.debug("[CRAWL WORKER] Waiting for URL from queue...")
                url_to_crawl = await self.crawl_queue.get()
                ctx.log.debug(
                    f"[CRAWL WORKER] Got URL: {url_to_crawl}. Waiting for semaphore..."
                )
                # Acquire semaphore to limit concurrency
                async with self.semaphore:
                    ctx.log.debug(
                        f"[CRAWL WORKER] Semaphore acquired for {url_to_crawl}. Starting GET request..."
                    )
                    try:
                        # Use the addon's shared http_client instance
                        response = await self.http_client.get(url_to_crawl)
                        # Note: This response does NOT automatically go through mitmproxy's hooks
                        # because the request was made by the script's internal client.
                        # If analysis of crawler responses is needed, it must happen here.
                        ctx.log.debug(
                            f"[CRAWLER TASK] Visited {url_to_crawl}, Status: {response.status_code}."
                        )
                        # TODO: Optionally parse crawler response here for more links? Risk of loops/depth issues.
                    except httpx.TimeoutException:
                        ctx.log.warn(f"[CRAWLER TASK] Timeout visiting {url_to_crawl}")
                    except Exception as e:
                        ctx.log.warn(
                            f"[CRAWLER TASK] Error visiting {url_to_crawl}: {e}"
                        )
                    finally:
                        ctx.log.debug(
                            f"[CRAWL WORKER] Releasing semaphore for {url_to_crawl}"
                        )
                        # Mark the queue task as done AFTER releasing the semaphore
                        self.crawl_queue.task_done()
            except asyncio.CancelledError:
                ctx.log.info("Crawl worker cancelled.")
                break  # Exit the while loop
            except Exception as e:
                ctx.log.critical(f"CRITICAL ERROR in Crawl Worker loop: {e}")
                # Pause to prevent busy-looping on continuous errors
                await asyncio.sleep(10)

    async def _scan_worker(self):
        """Asynchronous worker that processes the active scan queue."""
        ctx.log.info("Internal Scan Worker started.")
        while True:
            # Wait until the HTTP client is ready
            if not self.http_client:
                ctx.log.debug("[SCAN WORKER] HTTP client not ready, waiting...")
                await asyncio.sleep(0.5)
                continue
            try:
                ctx.log.debug("[SCAN WORKER] Waiting for target from queue...")
                scan_details = await self.scan_queue.get()
                # Log a shorter version of the URL for brevity
                target_url_short = scan_details.get("url", "N/A").split("?")[0]
                ctx.log.debug(
                    f"[SCAN WORKER] Got target: {scan_details.get('method')} {target_url_short}. Waiting for semaphore..."
                )
                # Acquire semaphore
                async with self.semaphore:
                    ctx.log.debug(
                        f"[SCAN WORKER] Semaphore acquired for {target_url_short}. Starting active scans..."
                    )
                    try:
                        cookies = scan_details.get("cookies", {})
                        # Call the imported scan functions, passing the shared client and details
                        # These functions use 'ctx' imported within their own modules for logging.
                        await scan_sqli_basic(scan_details, cookies, self.http_client)
                        await scan_xss_basic(scan_details, cookies, self.http_client)
                        # Add calls to other scan functions here...
                        ctx.log.debug(
                            f"[SCAN WORKER] Active scans completed for {target_url_short}."
                        )
                    except Exception as e:
                        # Log errors specific to scanning a particular target
                        ctx.log.error(
                            f"[SCAN TASK] Error during scan of {scan_details.get('url', 'N/A')}: {e}"
                        )
                    finally:
                        ctx.log.debug(
                            f"[SCAN WORKER] Releasing semaphore for {target_url_short}"
                        )
                        # Mark queue task as done AFTER releasing semaphore
                        self.scan_queue.task_done()
            except asyncio.CancelledError:
                ctx.log.info("Scan worker cancelled.")
                break  # Exit the while loop
            except Exception as e:
                ctx.log.critical(f"CRITICAL ERROR in Scan Worker loop: {e}")
                await asyncio.sleep(10)  # Pause on critical errors


# --- Addon Registration ---
addons = [MainAddon()]
