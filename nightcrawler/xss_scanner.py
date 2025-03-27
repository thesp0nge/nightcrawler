# nightcrawler/xss_scanner.py
import httpx
import time
import random
from mitmproxy import ctx
from typing import Dict, Any, TYPE_CHECKING

# Import payloads/config
from nightcrawler.config import (
    XSS_REFLECTED_PAYLOADS,
    XSS_STORED_PROBE_PREFIX,
    XSS_STORED_PAYLOAD_FORMAT,
)

# Type hint for MainAddon without circular import
if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon


# --- Reflected XSS Scan ---


async def scan_xss_reflected_basic(
    target_info: Dict[str, Any],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,
):
    """
    Attempts basic reflected XSS payloads by checking for immediate reflection
    in the response. Does NOT detect stored XSS.
    """
    payloads = XSS_REFLECTED_PAYLOADS  # Use specific reflected payloads
    url = target_info["url"]
    method = target_info["method"]
    original_params = target_info["params"]
    original_data = target_info["data"]
    headers = target_info["headers"]
    params_to_fuzz = list(original_params.keys()) + list(original_data.keys())
    if not params_to_fuzz:
        return  # No parameters to test

    ctx.log.debug(f"[XSS Reflected Scan] Starting for {url} (Params: {params_to_fuzz})")
    for param_name in params_to_fuzz:
        # ctx.log.debug(f"[XSS Reflected Scan] Fuzzing parameter: {param_name}") # Can be verbose
        for payload in payloads:
            current_params = original_params.copy()
            current_data = original_data.copy()
            is_param_in_query = param_name in current_params

            # Inject payload (replacing original value)
            if is_param_in_query:
                current_params[param_name] = payload
            else:
                current_data[param_name] = payload

            payload_info = (
                f"URL: {url}, Param: {param_name}, Payload Snippet: {payload[:30]}..."
            )
            try:
                # ctx.log.debug(f"[XSS Reflected Scan] Sending payload '{payload[:20]}...' to param '{param_name}'") # Verbose
                response = await http_client.request(
                    method,
                    url.split("?")[0] if is_param_in_query else url,
                    params=current_params if is_param_in_query else original_params,
                    data=current_data if not is_param_in_query else original_data,
                    headers=headers,
                    cookies=cookies,
                )
                # ctx.log.debug(f"[XSS Reflected Scan] Received response (Status: {response.status_code})") # Verbose

                # --- Basic Reflected XSS Response Analysis ---
                content_type = response.headers.get("Content-Type", "")
                if "html" in content_type:
                    response_text = ""
                    try:
                        response_text = response.text
                    except Exception:
                        pass  # Ignore decoding errors

                    # Check for exact, case-sensitive payload reflection
                    if response_text and payload in response_text:
                        ctx.log.error(f"[XSS FOUND? Reflected] {payload_info}")

            except httpx.TimeoutException:
                ctx.log.warn(
                    f"[XSS Reflected Scan] Timeout sending payload: {payload_info}"
                )
            except Exception as e:
                ctx.log.debug(
                    f"[XSS Reflected Scan] Exception during payload send/recv: {e} ({payload_info})"
                )
            # await asyncio.sleep(0.05) # Optional pause
    ctx.log.debug(f"[XSS Reflected Scan] Finished for {url}")


# --- Stored XSS Injection Attempt ---


async def scan_xss_stored_inject(
    target_info: Dict[str, Any],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,
    addon_instance: "MainAddon",  # Pass the addon instance for state access
):
    """
    Injects unique, trackable payloads into parameters for potential Stored XSS.
    It does NOT check the immediate response for reflection.
    """
    url = target_info["url"]
    method = target_info["method"]
    original_params = target_info["params"]
    original_data = target_info["data"]
    headers = target_info["headers"]
    params_to_fuzz = list(original_params.keys()) + list(original_data.keys())
    if not params_to_fuzz:
        return  # No parameters to test

    ctx.log.debug(
        f"[XSS Stored Inject] Starting injection attempts for {url} (Params: {params_to_fuzz})"
    )
    for param_name in params_to_fuzz:
        # Generate a unique payload ID for this specific injection point
        probe_id = f"{XSS_STORED_PROBE_PREFIX}_{int(time.time())}_{random.randint(1000,9999)}_{param_name}"
        # Format the actual payload string using the template from config
        unique_payload = XSS_STORED_PAYLOAD_FORMAT.format(probe_id=probe_id)

        # Create copies and inject payload (usually appending is better for stored checks)
        current_params = original_params.copy()
        current_data = original_data.copy()
        is_param_in_query = param_name in current_params
        original_value = (
            current_params.get(param_name)
            if is_param_in_query
            else current_data.get(param_name, "")
        )

        # Inject by appending the unique payload to the original value
        injected_value = original_value + unique_payload
        if is_param_in_query:
            current_params[param_name] = injected_value
        else:
            current_data[param_name] = injected_value

        payload_info = (
            f"URL: {url}, Param: {param_name}, ProbeID: {probe_id}"  # For logging
        )
        try:
            ctx.log.debug(
                f"[XSS Stored Inject] Sending probe '{probe_id}' to param '{param_name}' for {url.split('?')[0]}"
            )
            response = await http_client.request(
                method,
                url.split("?")[0] if is_param_in_query else url,
                params=current_params if is_param_in_query else original_params,
                data=current_data if not is_param_in_query else original_data,
                headers=headers,
                cookies=cookies,
            )
            ctx.log.debug(
                f"[XSS Stored Inject] Received response for probe '{probe_id}' (Status: {response.status_code})"
            )

            # --- Register the injection attempt ---
            # Store details about this injection attempt for later checking
            injection_details = {
                "url": url,
                "param_name": param_name,
                "method": method,
                "payload_used": unique_payload,  # Store the exact payload string injected
                "probe_id": probe_id,  # Store the unique ID
            }
            # Call the registration method on the main addon instance
            addon_instance.register_injection(probe_id, injection_details)

            # Optionally: Add URLs from the response (e.g., redirects) to the revisit queue?
            # if response.is_redirect:
            #    redirect_url = urljoin(url, response.headers.get('Location'))
            #    if is_in_scope(redirect_url, addon_instance.effective_scope): # Check scope
            #         addon_instance.revisit_queue.put_nowait(redirect_url)
            #         ctx.log.debug(f"[Revisit Queue] Added redirect {redirect_url} after probe {probe_id}")

        except httpx.TimeoutException:
            ctx.log.warn(f"[XSS Stored Inject] Timeout sending probe: {payload_info}")
        except Exception as e:
            ctx.log.debug(
                f"[XSS Stored Inject] Exception during probe send/recv: {e} ({payload_info})"
            )
        # await asyncio.sleep(0.05) # Optional pause between parameter injections
    ctx.log.debug(f"[XSS Stored Inject] Finished injection attempts for {url}")
