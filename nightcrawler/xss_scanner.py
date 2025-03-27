# nightcrawler/xss_scanner.py
import httpx
from mitmproxy import ctx
from typing import Dict, Any

# Import payloads from config (or define them here)
from nightcrawler.config import XSS_PAYLOADS


async def scan_xss_basic(
    target_info: Dict[str, Any],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,  # Passed from main_addon
):
    """Attempts basic reflected XSS payloads by checking for reflection."""
    # WARNING: This logic does NOT detect Stored XSS.
    payloads = XSS_PAYLOADS
    url = target_info["url"]
    method = target_info["method"]
    original_params = target_info["params"]
    original_data = target_info["data"]
    headers = target_info["headers"]
    params_to_fuzz = list(original_params.keys()) + list(original_data.keys())
    if not params_to_fuzz:
        return  # No parameters to test

    ctx.log.debug(
        f"[XSS Scan] Starting basic XSS scan for {url} (Params: {params_to_fuzz})"
    )
    for param_name in params_to_fuzz:
        ctx.log.debug(f"[XSS Scan] Fuzzing parameter: {param_name}")
        for payload in payloads:
            # Create copies and inject payload (replacing original value)
            current_params = original_params.copy()
            current_data = original_data.copy()
            is_param_in_query = param_name in current_params

            if is_param_in_query:
                current_params[param_name] = payload
            else:
                current_data[param_name] = payload

            payload_info = f"URL: {url}, Param: {param_name}, Payload Snippet: {payload[:30]}..."  # For logging
            try:
                ctx.log.debug(
                    f"[XSS Scan] Sending payload '{payload[:20]}...' to param '{param_name}' for {url.split('?')[0]}"
                )
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
                ctx.log.debug(
                    f"[XSS Scan] Received response for payload '{payload[:20]}...' (Status: {response.status_code})"
                )

                # --- Basic XSS Response Analysis (Simple Reflection) ---
                content_type = response.headers.get("Content-Type", "")
                # Check only if the response looks like HTML and the exact payload is present
                # This is a very naive check, easily bypassed by encoding, context changes, etc.
                if "html" in content_type:
                    response_text = ""
                    try:
                        response_text = response.text  # Decode response body
                    except Exception:
                        pass  # Ignore decoding errors

                    # Check for exact, case-sensitive payload reflection
                    if response_text and payload in response_text:
                        ctx.log.error(f"[XSS FOUND? Reflected] {payload_info}")

            except httpx.TimeoutException:
                ctx.log.warn(f"[XSS Scan] Timeout sending payload: {payload_info}")
            except Exception as e:
                ctx.log.debug(
                    f"[XSS Scan] Exception during payload send/recv: {e} ({payload_info})"
                )

            # Optional: Short pause between payloads?
            # await asyncio.sleep(0.05)

    ctx.log.debug(f"[XSS Scan] Finished basic XSS scan for {url}")
