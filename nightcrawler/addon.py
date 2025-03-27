# nightcrawler/addon.py
import mitmproxy.http
from mitmproxy import ctx, http, addonmanager
import asyncio
import httpx
import time
from typing import Set, Dict, Any, Optional

# --- Imports from local package modules ---
try:
    from nightcrawler.config import MAX_CONCURRENT_SCANS, USER_AGENT  # Scope removed
    from nightcrawler.utils import is_in_scope, create_target_signature
    from nightcrawler.passive_scanner import run_all_passive_checks
    from nightcrawler.crawler import parse_and_queue_links
    from nightcrawler.sqli_scanner import scan_sqli_basic

    # Import both XSS scanning functions
    from nightcrawler.xss_scanner import (
        scan_xss_reflected_basic,
        scan_xss_stored_inject,
    )
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
    crawling, basic active scanning (Reflected + Stored XSS injection/check).
    Scope is defined via the --nc-scope command-line option.
    """

    def __init__(self):
        """Initializes the addon's state."""
        self.discovered_urls: Set[str] = set()
        self.scanned_targets: Set[str] = set()
        self.scan_queue: asyncio.Queue = asyncio.Queue()
        self.crawl_queue: asyncio.Queue = asyncio.Queue()
        # State for Stored XSS detection
        self.revisit_queue: asyncio.Queue = asyncio.Queue()
        self.injected_payloads: Dict[str, Dict[str, Any]] = {}  # probe_id -> {details}

        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
        self.http_client: Optional[httpx.AsyncClient] = None
        # Background task references
        self.crawl_worker_task: Optional[asyncio.Task] = None
        self.scan_worker_task: Optional[asyncio.Task] = None
        self.revisit_worker_task: Optional[asyncio.Task] = (
            None  # Task for the new worker
        )

        self.effective_scope: Set[str] = set()  # Scope set via command line option

        ctx.log.info("=" * 30)
        ctx.log.info(" Main Addon v0.5 (Stored XSS Basic) Initialized ")
        ctx.log.info("=" * 30)

    def load(self, loader: addonmanager.Loader):
        """Hook called on startup to load options."""
        loader.add_option(
            name="nc_scope",
            type=str,
            default="",
            help="Target scope domain(s), comma-separated (e.g., example.com,sub.example.com). Required for processing.",
        )
        # Add option to control max age of tracked payloads?
        loader.add_option(
            name="nc_payload_max_age",
            type=int,
            default=3600,  # 1 hour default
            help="Max age (seconds) for tracking injected payloads for Stored XSS.",
        )

    def configure(self, updated: Set[str]):
        """Hook called when options are set or updated."""
        if "nc_scope" in updated:
            scope_str = ctx.options.nc_scope
            if scope_str:
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

        # Log other config only once on initial setup
        if not updated:
            ctx.log.debug(f"Max Worker Concurrency: {MAX_CONCURRENT_SCANS}")
            ctx.log.debug(f"Scan/Crawl User Agent: {USER_AGENT}")
            ctx.log.debug(f"Tracked Payload Max Age: {ctx.options.nc_payload_max_age}s")

    def running(self):
        """Hook called when mitmproxy is ready."""
        if not self.http_client:
            self.http_client = httpx.AsyncClient(
                headers={"User-Agent": USER_AGENT},
                verify=False,
                timeout=15.0,
                follow_redirects=True,
                limits=httpx.Limits(
                    max_connections=MAX_CONCURRENT_SCANS + 5,
                    max_keepalive_connections=MAX_CONCURRENT_SCANS,
                ),
            )
        # Start all worker tasks if not already running
        if not self.crawl_worker_task or self.crawl_worker_task.done():
            self.crawl_worker_task = asyncio.create_task(self._crawl_worker())
        if not self.scan_worker_task or self.scan_worker_task.done():
            self.scan_worker_task = asyncio.create_task(self._scan_worker())
        if (
            not self.revisit_worker_task or self.revisit_worker_task.done()
        ):  # Start the new worker
            self.revisit_worker_task = asyncio.create_task(self._revisit_worker())

        if not self.effective_scope:
            ctx.log.warn("REMINDER: No target scope set via --nc-scope.")
        ctx.log.info("Background workers started (Crawl, Scan, Revisit).")

    async def done(self):
        """Hook called on shutdown for resource cleanup."""
        ctx.log.info("Main Addon: Shutting down...")
        tasks_to_cancel: list[asyncio.Task] = []
        if self.scan_worker_task and not self.scan_worker_task.done():
            self.scan_worker_task.cancel()
            tasks_to_cancel.append(self.scan_worker_task)
        if self.crawl_worker_task and not self.crawl_worker_task.done():
            self.crawl_worker_task.cancel()
            tasks_to_cancel.append(self.crawl_worker_task)
        if (
            self.revisit_worker_task and not self.revisit_worker_task.done()
        ):  # Cancel new worker
            self.revisit_worker_task.cancel()
            tasks_to_cancel.append(self.revisit_worker_task)

        if tasks_to_cancel:
            try:
                await asyncio.gather(*tasks_to_cancel, return_exceptions=True)
                ctx.log.info("Worker tasks cancelled.")
            except asyncio.CancelledError:
                ctx.log.debug("Gather cancelled (expected during shutdown).")

        if self.http_client:
            await self.http_client.aclose()
            ctx.log.info("Shared HTTP client closed.")
            self.http_client = None
        ctx.log.info("Main Addon: Shutdown complete.")

    # --- Method to Register Injected Payloads ---
    def register_injection(self, probe_id: str, injection_details: Dict[str, Any]):
        """Registers details about an injected payload for Stored XSS checks."""
        if not probe_id:
            return
        details = injection_details.copy()
        details["timestamp"] = time.time()
        self.injected_payloads[probe_id] = details
        ctx.log.debug(
            f"[Injection Tracking] Registered probe {probe_id} from {details.get('url')}, param '{details.get('param_name')}'"
        )

        # --- Optional: Cleanup old payloads ---
        # Simple cleanup based on count, could also use timestamp from details
        max_tracked_payloads = 5000  # Limit memory usage
        if len(self.injected_payloads) > max_tracked_payloads:
            # Remove the oldest items (requires ordered dict or sorting)
            # Simple approach: remove a random old one (less precise)
            try:
                # Get oldest N keys based on timestamp if available
                num_to_remove = len(self.injected_payloads) - max_tracked_payloads
                # Sort by timestamp (oldest first)
                oldest_ids = sorted(
                    self.injected_payloads,
                    key=lambda k: self.injected_payloads[k].get("timestamp", 0),
                )
                for i in range(num_to_remove):
                    if oldest_ids:
                        del self.injected_payloads[oldest_ids[i]]
                ctx.log.debug(f"Cleaned up {num_to_remove} oldest tracked payloads.")
            except Exception as e:
                ctx.log.warn(f"Error during payload cleanup: {e}")

    # --- Method to Check Responses for Stored Payloads ---
    def check_response_for_stored_payloads(
        self, response_text: str | None, current_url: str
    ):
        """Checks if any tracked payloads appear in the given HTML content."""
        if not response_text or not self.injected_payloads:
            return

        found_payload_ids = []
        # Iterate over tracked payload IDs
        # Use list copy for safe iteration if items might be removed (though not currently removing on find)
        payload_ids_to_check = list(self.injected_payloads.keys())

        for probe_id in payload_ids_to_check:
            # Check if the unique probe ID exists in the response text
            # This is a basic string check. Could use regex or parsing for more robustness.
            # Check against the specific format used in injection, e.g., the comment
            payload_format_used = XSS_STORED_PAYLOAD_FORMAT  # Get from config
            payload_to_find = payload_format_used.format(probe_id=probe_id)

            if payload_to_find in response_text:
                # Basic check passed, log potential finding
                injection_info = self.injected_payloads.get(probe_id, {})
                ctx.log.error(
                    f"[STORED XSS? FOUND] Probe ID: {probe_id} "
                    f"(Injected at: {injection_info.get('url')} / Param: '{injection_info.get('param_name')}') "
                    f"FOUND at URL: {current_url}"
                )
                found_payload_ids.append(probe_id)
                # Optionally add a 'found_at' list to injection_info instead of just logging

        if found_payload_ids:
            ctx.log.debug(
                f"Found {len(found_payload_ids)} potential stored probe(s) in {current_url}"
            )

        # Optional: Implement cleanup based on timestamp using nc_payload_max_age
        current_time = time.time()
        max_age = ctx.options.nc_payload_max_age
        ids_to_remove = {
            pid
            for pid, details in self.injected_payloads.items()
            if current_time - details.get("timestamp", 0) > max_age
        }
        if ids_to_remove:
            ctx.log.debug(
                f"Removing {len(ids_to_remove)} tracked payloads older than {max_age}s."
            )
            for pid in ids_to_remove:
                try:
                    del self.injected_payloads[pid]
                except KeyError:
                    pass  # Already removed

    # --- HTTP Hooks ---
    def request(self, flow: http.HTTPFlow) -> None:
        """Processes intercepted client requests."""
        if not self.effective_scope or not is_in_scope(
            flow.request.pretty_url, self.effective_scope
        ):
            return

        url = flow.request.pretty_url
        if url not in self.discovered_urls:
            self.discovered_urls.add(url)
            ctx.log.info(f"[DISCOVERY] Added URL (from Browse): {url}")

        target_signature = create_target_signature(flow.request)
        if target_signature and target_signature not in self.scanned_targets:
            self.scanned_targets.add(target_signature)
            scan_details = {
                "url": url,
                "method": flow.request.method,
                "params": dict(flow.request.query or {}),
                "data": dict(flow.request.urlencoded_form or {}),
                "headers": dict(flow.request.headers),
                "cookies": dict(flow.request.cookies or {}),
            }
            self.scan_queue.put_nowait(scan_details)
            ctx.log.debug(
                f"[SCAN QUEUE] Add Target: {target_signature} (Qsize: {self.scan_queue.qsize()})"
            )

    def response(self, flow: http.HTTPFlow) -> None:
        """Processes intercepted server responses."""
        if not self.effective_scope or not is_in_scope(
            flow.request.pretty_url, self.effective_scope
        ):
            return

        # 1. Run passive checks
        run_all_passive_checks(flow)

        # 2. Parse for crawl links if HTML
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
                self.effective_scope,
            )

        # 3. Check this response for *previously injected* stored payloads
        #    This covers cases where Browse triggers display of stored data
        self.check_response_for_stored_payloads(
            flow.response.text, flow.request.pretty_url
        )

    # --- Background Workers ---

    async def _crawl_worker(self):
        """Asynchronous worker that processes the crawl queue."""
        ctx.log.info("Internal Crawl Worker started.")
        while True:
            if not self.http_client:
                await asyncio.sleep(0.5)
                continue
            try:
                url_to_crawl = await self.crawl_queue.get()
                # ctx.log.debug(f"[CRAWL WORKER] Got URL: {url_to_crawl}. Waiting for semaphore...") # Verbose
                async with self.semaphore:
                    # ctx.log.debug(f"[CRAWL WORKER] Semaphore acquired for {url_to_crawl}.") # Verbose
                    try:
                        response = await self.http_client.get(url_to_crawl)
                        ctx.log.debug(
                            f"[CRAWLER TASK] Visited {url_to_crawl}, Status: {response.status_code}."
                        )
                        # --- Check crawler response for stored payloads ---
                        # The crawler might stumble upon pages displaying stored payloads
                        self.check_response_for_stored_payloads(
                            response.text, url_to_crawl
                        )
                        # --- Optionally parse crawler response for more links ---
                        # Be cautious about recursion depth and scope re-checking here
                        # content_type = response.headers.get("Content-Type", "")
                        # if 200 <= response.status_code < 300 and "html" in content_type:
                        #    parse_and_queue_links(response.text, str(response.url), self.discovered_urls, self.crawl_queue, self.effective_scope)

                    except httpx.TimeoutException:
                        ctx.log.warn(f"[CRAWLER TASK] Timeout visiting {url_to_crawl}")
                    except Exception as e:
                        ctx.log.warn(
                            f"[CRAWLER TASK] Error visiting {url_to_crawl}: {e}"
                        )
                    # finally:
                    # ctx.log.debug(f"[CRAWL WORKER] Releasing semaphore for {url_to_crawl}") # Verbose
                self.crawl_queue.task_done()
            except asyncio.CancelledError:
                ctx.log.info("Crawl worker cancelled.")
                break
            except Exception as e:
                ctx.log.critical(f"CRITICAL ERROR in Crawl Worker loop: {e}")
                await asyncio.sleep(10)

    async def _scan_worker(self):
        """Asynchronous worker that processes the active scan queue."""
        ctx.log.info("Internal Scan Worker started.")
        while True:
            if not self.http_client:
                await asyncio.sleep(0.5)
                continue
            try:
                scan_details = await self.scan_queue.get()
                target_url_short = scan_details.get("url", "N/A").split("?")[0]
                # ctx.log.debug(f"[SCAN WORKER] Got target: {scan_details.get('method')} {target_url_short}. Waiting for semaphore...") # Verbose
                async with self.semaphore:
                    ctx.log.debug(
                        f"[SCAN WORKER] Semaphore acquired for {target_url_short}. Starting scans..."
                    )
                    try:
                        cookies = scan_details.get("cookies", {})
                        target_method = scan_details.get("method", "GET").upper()

                        # --- Call Scan Functions ---
                        # 1. Basic SQLi Scan
                        await scan_sqli_basic(scan_details, cookies, self.http_client)

                        # 2. Basic Reflected XSS Scan
                        await scan_xss_reflected_basic(
                            scan_details, cookies, self.http_client
                        )

                        # 3. Stored XSS Injection Attempt (passing self for state access)
                        await scan_xss_stored_inject(
                            scan_details, cookies, self.http_client, self
                        )

                        # --- Trigger Revisit Check ---
                        # If the request might have stored data (POST/PUT etc.), queue URL for revisit
                        if target_method in ["POST", "PUT", "PATCH"]:
                            revisit_url = scan_details[
                                "url"
                            ]  # Revisit the same URL for now
                            # TODO: Smarter revisit strategy? Check redirects? Common display pages?
                            if (
                                revisit_url not in self.revisit_queue._queue
                            ):  # Avoid adding duplicates quickly
                                ctx.log.debug(
                                    f"[Revisit Queue] Adding {revisit_url} for post-injection check. Qsize: {self.revisit_queue.qsize()}"
                                )
                                self.revisit_queue.put_nowait(revisit_url)

                        ctx.log.debug(
                            f"[SCAN WORKER] Scans finished for {target_url_short}."
                        )
                    except Exception as e:
                        ctx.log.error(
                            f"[SCAN TASK] Error during scan of {scan_details.get('url', 'N/A')}: {e}"
                        )
                    # finally:
                    # ctx.log.debug(f"[SCAN WORKER] Releasing semaphore for {target_url_short}") # Verbose
                self.scan_queue.task_done()
            except asyncio.CancelledError:
                ctx.log.info("Scan worker cancelled.")
                break
            except Exception as e:
                ctx.log.critical(f"CRITICAL ERROR in Scan Worker loop: {e}")
                await asyncio.sleep(10)

    async def _revisit_worker(self):
        """Asynchronous worker that revisits URLs to check for stored payloads."""
        ctx.log.info("Internal Revisit Worker started.")
        while True:
            if not self.http_client:
                await asyncio.sleep(0.5)
                continue
            try:
                url_to_revisit = await self.revisit_queue.get()
                # ctx.log.debug(f"[Revisit Worker] Got URL: {url_to_revisit}. Waiting for semaphore...") # Verbose
                async with self.semaphore:  # Share semaphore with other workers
                    # ctx.log.debug(f"[Revisit Worker] Semaphore acquired for {url_to_revisit}. Fetching page...") # Verbose
                    try:
                        # Use GET by default for revisiting, maybe need smarter logic?
                        # Pass cookies? Maybe needs session handling. For now, simple GET.
                        response = await self.http_client.get(url_to_revisit)
                        ctx.log.debug(
                            f"[Revisit Worker] Fetched {url_to_revisit}, Status: {response.status_code}. Checking for stored payloads..."
                        )
                        # Call the checking function
                        self.check_response_for_stored_payloads(
                            response.text, url_to_revisit
                        )
                    except httpx.TimeoutException:
                        ctx.log.warn(
                            f"[Revisit Worker] Timeout fetching {url_to_revisit}"
                        )
                    except Exception as e:
                        ctx.log.warn(
                            f"[Revisit Worker] Error fetching {url_to_revisit}: {e}"
                        )
                    # finally:
                    # ctx.log.debug(f"[Revisit Worker] Releasing semaphore for {url_to_revisit}") # Verbose
                self.revisit_queue.task_done()
            except asyncio.CancelledError:
                ctx.log.info("Revisit worker cancelled.")
                break
            except Exception as e:
                ctx.log.critical(f"CRITICAL ERROR in Revisit Worker loop: {e}")
                await asyncio.sleep(10)


# --- Addon Registration ---
addons = [MainAddon()]
