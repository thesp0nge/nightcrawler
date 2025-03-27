# Nightcrawler

A mitmproxy addon for background passive analysis, crawling, and basic active
scanning, designed as a security researcher's sidekick.

**WARNING: Beta Stage - Use with caution, especially active scanning features**

## FEATURES

- Acts as an HTTP/HTTPS proxy.
- Performs passive analysis (security headers, cookie attributes, basic info
  disclosure).
- Crawls the target application to discover new endpoints based on visited
  pages.
- Runs basic active scans for low-hanging fruit (Reflected XSS, basic SQLi -
  Error/Time-based) in the background.
- All output and logs are directed to the console.
- Target scope is configurable via command-line argument.

## INSTALLATION

You can install `nightcrawler` directly from PyPI using pip:

pip install nightcrawler

It's recommended to install it in a virtual environment.

## USAGE

Once installed, a new command `nightcrawler` becomes available. This command
wraps `mitmdump`, automatically loading the nightcrawler addon. You MUST specify
the target scope using the `--nc-scope` option.

You can pass any other valid `mitmdump` arguments to the `nightcrawler` command.

1. Configure your Browser/Client: Set your browser (or system) to use 127.0.0.1
   on port 8080 (or the port you specify using -p) as its HTTP and HTTPS proxy.

2. Install Mitmproxy CA Certificate: For HTTPS interception, ensure the
   mitmproxy CA certificate is installed and trusted in your browser/system.
   While the proxy is running, visit <http://mitm.it> and follow the
   instructions.

3. Run Nightcrawler:

   - Specify Target Scope (REQUIRED!): nightcrawler --nc-scope example.com

   - Multiple domains (comma-separated, no spaces): nightcrawler --nc-scope
     example.com,sub.example.com,another.net

   - Common Options: (Specify port and scope) nightcrawler -p 8081 --nc-scope
     example.com

     (Disable upstream certificate verification + scope - USE WITH CAUTION!)
     nightcrawler --ssl-insecure --nc-scope internal-site.local

     (Increase verbosity + scope - Use -v for DEBUG logs) nightcrawler -v
     --nc-scope example.com

     (Combine options) nightcrawler -p 8080 --ssl-insecure -v --nc-scope
     dev.example.com

   NOTE: If --nc-scope is not provided, Nightcrawler will run but will not
   process any requests.

4. Browse: Start Browse the target application(s) specified in the scope. Output
   from passive analysis, crawling, and active scans will appear in the terminal
   where `nightcrawler` is running. Look for [Passive Scan], [CRAWLER
   DISCOVERY],
   [SQLi FOUND?], [XSS FOUND?] messages.

## CONFIGURATION

- Target Scope (Required): Set via the `--nc-scope` command-line argument
  (comma-separated domains).

- Other Settings: Max concurrency (MAX_CONCURRENT_SCANS) and User-Agent
  (USER_AGENT) are currently defined in the `nightcrawler/config.py` file within
  the installed package. Modifying these requires editing the installed file
  (future versions may use command-line options or a separate config file). You
  can find the installation location using `pip show nightcrawler-mitm`.

## LIMITATIONS

- Basic Active Scans: The SQLi and XSS scanners are very basic and intended only
  for obvious low-hanging fruit. They CANNOT detect complex vulnerabilities
  (e.g., Stored XSS, blind SQLi beyond time-based, DOM XSS, template injection,
  etc.). DO NOT rely solely on this tool for comprehensive vulnerability
  assessment.

- Stored XSS: The current XSS scanner only checks for immediate reflection and
  CANNOT detect Stored XSS.

- Resource Usage: Background crawling and scanning can consume significant
  network bandwidth, CPU, and memory resources. Adjust MAX_CONCURRENT_SCANS in
  `config.py` if needed.

- False Positives/Negatives: Expect potential false positives (especially from
  passive checks or simple XSS reflection) and many false negatives
  (vulnerabilities missed by the basic scanners).

## LICENSE

This project is licensed under the [MIT License]. See the LICENSE file for details.

## CONTRIBUTING (Optional)

Contributions are welcome! Please open an issue or submit a pull request on the
GitHub repository: [https://github.com/thesp0nge/nightcrawler]
