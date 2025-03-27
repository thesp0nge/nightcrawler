# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- _Future features go here_

### Changed

- _Future changes go here_

### Fixed

- _Future fixes go here_

## [0.3.0] - 2025-03-27

### Added

- **Basic Stored XSS Detection:** Implemented initial capability to detect
  stored XSS vulnerabilities.
  - Injects unique, trackable probes (e.g., ``) via `scan_xss_stored_inject`.
  - Tracks injected probes in memory within the main addon
    (`MainAddon.injected_payloads`).
  - Added a background "Revisit Worker" (`_revisit_worker`) and queue
    (`revisit_queue`) to re-fetch URLs after potential storage actions
    (POST/PUT).
  - Checks HTML content of revisited pages, regular browser responses, and
    crawler responses for the presence of previously injected unique probes via
    `check_response_for_stored_payloads`.
  - Added basic time-based and count-based cleanup for tracked payloads to limit
    memory usage.
  - Added `--nc-payload-max-age` command-line option (via `ctx.options`) to
    configure the maximum age (in seconds) for tracked payloads.
- Separated XSS scanning logic into distinct functions
  (`scan_xss_reflected_basic`, `scan_xss_stored_inject`) in `xss_scanner.py` for
  better maintainability.
- Added check for stored payloads in responses fetched by the `_crawl_worker`.

### Changed

- Significantly updated `addon.py` (`MainAddon`) to manage state (queues,
  tracked payloads) and the new `_revisit_worker` required for Stored XSS
  detection.
- Renamed original XSS scan function `scan_xss_basic` to
  `scan_xss_reflected_basic`.
- Updated `config.py` to hold separate configuration/payloads for reflected
  (`XSS_REFLECTED_PAYLOADS`) vs. stored (`XSS_STORED_PROBE_PREFIX`,
  `XSS_STORED_PAYLOAD_FORMAT`) XSS checks.
- Modified `xss_scanner.py` to include the new `scan_xss_stored_inject` function
  and pass the addon instance for state access (`register_injection`).
- Added cleanup logic in the `done` hook for the new `revisit_worker_task`.

## [0.2.0] - 2025-03-25

### Added

- Packaged the project using `pyproject.toml` for installation via `pip` and
  distribution on PyPI (as `nightcrawler`).
- Introduced a console script entry point: the `nightcrawler` command now wraps
  `mitmdump` and loads the addon automatically.
- Added a **mandatory** command-line option `--nc-scope` to define the target
  domain(s) for scanning and crawling (comma-separated).
- Implemented `--version` handling for the `nightcrawler` command to display the
  package's own version alongside mitmproxy's version.
- Added basic addon lifecycle management using `running` and `done` hooks
  (starting workers, closing shared HTTP client).
- Included basic `try...except` blocks in worker loops to improve resilience
  against unexpected errors.

### Changed

- **Major Refactor:** Restructured the single-script addon into multiple Python
  modules (`addon.py`, `config.py`, `utils.py`, `passive_scanner.py`,
  `crawler.py`, `sqli_scanner.py`, `xss_scanner.py`, `runner.py`) within a
  `nightcrawler` package directory for better organization and maintainability.
- Internal imports updated to use absolute package paths (e.g.,
  `from nightcrawler.utils import ...`).

### Removed

- Removed the hardcoded `TARGET_SCOPE_DOMAINS` constant from `config.py`; scope
  must now be provided via `--nc-scope`.

## [0.1.0] - 2025-03-20

### Added

- Initial version based on concept discussions.
- Core functionality as a `mitmproxy` addon script.
- Acts as an HTTP/HTTPS proxy.
- Basic passive scanning infrastructure (header/cookie checks - conceptual).
- Background crawling functionality (link discovery via `BeautifulSoup`, queuing
  via `asyncio.Queue`, basic `_crawl_worker`).
- Background active scanning worker (`_scan_worker`).
- Basic Reflected XSS scanning (`scan_xss_basic` checking immediate response).
- Basic SQLi scanning (`scan_sqli_basic` checking for errors/time delays).
- Concurrency limiting for background tasks using `asyncio.Semaphore`.
- Basic debug logging implemented using `ctx.log`.
- Support for `mitmproxy` options like `--ssl-insecure` passed through via the
  runner.

[Unreleased]: https://github.com/thesp0nge/nightcrawler/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/thesp0nge/nightcrawler/compare/v0.2.0...v0.3.0
