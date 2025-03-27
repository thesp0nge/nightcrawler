# nightcrawler/sqli_scanner.py
import httpx
import time
from mitmproxy import ctx
from typing import Dict, Any

# Import payloads from config (or define them here)
from nightcrawler.config import SQLI_PAYLOADS


async def scan_sqli_basic(
    target_info: Dict[str, Any],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,  # Passed from main_addon
):
    """Attempts some basic SQL injection payloads."""
    payloads = SQLI_PAYLOADS
    url = target_info["url"]
    method = target_info["method"]
    original_params = target_info["params"]
    original_data = target_info["data"]
    headers = target_info["headers"]
    # Parameters to fuzz (from GET query and POST form data)
    params_to_fuzz = list(original_params.keys()) + list(original_data.keys())
    if not params_to_fuzz:
        return  # No parameters to test

    ctx.log.debug(
        f"[SQLi Scan] Starting basic SQLi scan for {url} (Params: {params_to_fuzz})"
    )
    for param_name in params_to_fuzz:
        ctx.log.debug(f"[SQLi Scan] Fuzzing parameter: {param_name}")
        for payload in payloads:
            # Create copies of original data to inject the payload
            current_params = original_params.copy()
            current_data = original_data.copy()
            is_param_in_query = param_name in current_params
            # Get original value to append payload (or replace if needed)
            original_value = (
                current_params.get(param_name)
                if is_param_in_query
                else current_data.get(param_name, "")
            )

            # Inject payload by appending
            if is_param_in_query:
                current_params[param_name] = original_value + payload
            else:
                current_data[param_name] = original_value + payload

            payload_info = f"URL: {url}, Param: {param_name}, Payload: {payload}"  # For logging findings/errors
            try:
                ctx.log.debug(
                    f"[SQLi Scan] Sending payload '{payload}' to param '{param_name}' for {url.split('?')[0]}"
                )
                start_time = time.time()
                response = await http_client.request(
                    method,
                    url.split("?")[0]
                    if is_param_in_query
                    else url,  # Base URL if modifying query params
                    params=current_params if is_param_in_query else original_params,
                    data=current_data if not is_param_in_query else original_data,
                    headers=headers,
                    cookies=cookies,
                )
                duration = time.time() - start_time
                ctx.log.debug(
                    f"[SQLi Scan] Received response for payload '{payload}' (Status: {response.status_code}, Duration: {duration:.2f}s)"
                )

                # --- Basic SQLi Response Analysis ---
                # TODO: Make patterns configurable or more robust
                error_patterns = [
                    "sql syntax",
                    "unclosed quotation",
                    "odbc",
                    "ora-",
                    "invalid sql",
                    "syntax error",
                    "you have an error in your sql",
                ]
                response_text_lower = ""
                try:
                    # Only analyze text-based responses
                    # Check content-type? Maybe too restrictive for error messages.
                    response_text_lower = response.text.lower()
                except Exception:
                    pass  # Ignore if body cannot be decoded as text

                # 1. Error-Based Check
                if response_text_lower and any(
                    pattern in response_text_lower for pattern in error_patterns
                ):
                    ctx.log.error(f"[SQLi FOUND? Error-Based] {payload_info}")

                # 2. Time-Based Check (adjust threshold based on payload, e.g., SLEEP(5))
                if "SLEEP" in payload.upper() and duration > 4.5:  # Threshold near 5s
                    ctx.log.error(
                        f"[SQLi FOUND? Time-Based] {payload_info}, Duration: {duration:.2f}s"
                    )

                # NOTE: Lacks boolean-based, union-based, out-of-band detection. Very limited.

            except httpx.TimeoutException:
                ctx.log.warn(f"[SQLi Scan] Timeout sending payload: {payload_info}")
            except Exception as e:
                # Log exceptions during the request/response handling for a specific payload
                ctx.log.debug(
                    f"[SQLi Scan] Exception during payload send/recv: {e} ({payload_info})"
                )

            # Optional: Short pause between payloads?
            # await asyncio.sleep(0.05)

    ctx.log.debug(f"[SQLi Scan] Finished basic SQLi scan for {url}")
