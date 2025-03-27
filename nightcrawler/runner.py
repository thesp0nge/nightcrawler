# nightcrawler/runner.py
import sys
import os
from mitmproxy.tools.main import mitmdump  # Import mitmdump's main entry function

# Import the version defined in the package's __init__.py
try:
    # Assuming you have __version__ = "..." in nightcrawler/__init__.py
    from nightcrawler import __version__ as nightcrawler_version
except ImportError:
    # Fallback if __init__.py or __version__ is missing
    nightcrawler_version = "unknown"


def main():
    """
    Entry point for the 'nightcrawler' command line tool.
    Checks for the '--version' flag, otherwise starts mitmdump
    instructing it to load the addon from within this package.
    """
    # --- Intercept the --version argument ---
    if "--version" in sys.argv:
        print(f"Nightcrawler version: {nightcrawler_version}")
        # Optionally, also show the mitmproxy version for context.
        try:
            # Try to import and print the mitmproxy version
            from mitmproxy import version as mitmproxy_version_module

            print(f"Mitmproxy version: {mitmproxy_version_module.VERSION}")
        except ImportError:
            # Fallback if mitmproxy version cannot be imported
            print("Mitmproxy version: (could not determine)")
        # Exit immediately after printing the version(s)
        sys.exit(0)

    # --- If not --version, proceed to run mitmdump ---
    # Python path to the addon module within the package
    addon_path = "nightcrawler.addon"

    # Base arguments for mitmdump: load our addon script
    mitm_args = ["-s", addon_path]

    # Append all other arguments passed by the user to the 'nightcrawler' command
    # Skips the first argument (the command name itself)
    mitm_args.extend(sys.argv[1:])

    # Print an informational startup message to stderr
    print(f"--- Starting Nightcrawler (using addon: {addon_path}) ---", file=sys.stderr)
    # Useful for debugging: shows the effective mitmdump command being run
    # print(f"--- Running: mitmdump {' '.join(mitm_args)} ---", file=sys.stderr) # Uncomment if needed

    try:
        # Execute mitmdump with the combined arguments
        # This call replaces the current process with mitmdump
        mitmdump(mitm_args)
    except Exception as e:
        # Catch potential errors during mitmdump execution
        print(f"\n--- ERROR running mitmdump ---", file=sys.stderr)
        print(f"{e}", file=sys.stderr)
        print(f"--- Args passed: {' '.join(mitm_args)} ---", file=sys.stderr)
        sys.exit(1)  # Exit with a non-zero status code on error


if __name__ == "__main__":
    # Allows running this script directly (python nightcrawler/runner.py ...)
    # for testing, though the main entry point is the 'main' function
    # via the console script defined in pyproject.toml.
    main()

