# nightcrawler/runner.py
import sys
import os
from mitmproxy.tools.main import mitmdump  # Import mitmdump's main entry function


def main():
    """
    Entry point for the 'nightcrawler' command.
    Starts mitmdump, instructing it to load the addon from within this package.
    """
    # The Python path to the addon module within the package
    # mitmproxy should be able to load this using dot notation.
    addon_path = "nightcrawler.addon"

    # Base arguments for mitmdump: load our addon script
    mitm_args = ["-s", addon_path]

    # Append all arguments passed by the user to the 'nightcrawler' command
    # (e.g., --ssl-insecure, -p PORT, -v, etc.)
    # Skip the first argument, which is the command name itself ('nightcrawler')
    mitm_args.extend(sys.argv[1:])

    # Print an informational message to stderr
    print(f"--- Starting Nightcrawler (using addon: {addon_path}) ---", file=sys.stderr)
    # Useful for debugging: show the effective mitmdump command being run
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
        sys.exit(1)  # Exit with a non-zero status code


if __name__ == "__main__":
    # Allows running this script directly for testing purposes,
    # although the primary entry point is the 'main' function via the console script.
    main()
