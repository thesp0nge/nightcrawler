# nightcrawler/config.py

# --- Core Configuration ---
# Scope is set via command-line option '--nc-scope'

# Limit the maximum number of concurrent background crawl/scan tasks
MAX_CONCURRENT_SCANS = 5

# User Agent string for requests generated by the script (crawler/scanner)
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# --- Payloads ---
# Payloads for basic Reflected XSS checks (checking immediate response)
XSS_REFLECTED_PAYLOADS = [
    "<script>alert('XSSR')</script>",
    "\"><script>alert('XSSR')</script>",
    "'\"/><svg/onload=alert('XSSR')>",
    # Add more simple reflected payloads if desired
]

# Prefix for unique probe IDs used in Stored XSS checks
XSS_STORED_PROBE_PREFIX = "ncXSS"

# Format for the unique payload injected for Stored XSS detection.
# Using an HTML comment is often safer and less likely to break layouts.
# The {probe_id} will be replaced with the unique generated ID.
XSS_STORED_PAYLOAD_FORMAT = ""
# Alternative using a data attribute: "<span data-ncxss-probe='{probe_id}'></span>"

# Payloads for basic SQLi checks
SQLI_PAYLOADS = ["'", '"', "''", "' OR '1'='1", "' OR SLEEP(5)--"]

# Optional log file path
# LOG_FILE_PATH = "scan_findings.log"
