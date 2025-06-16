import argparse
import logging
import requests
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Analyzes HTTP response headers for common security misconfigurations."
    )
    parser.add_argument("url", help="The URL to analyze.")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging."
    )
    return parser


def analyze_headers(url):
    """
    Analyzes HTTP response headers for potential security vulnerabilities.
    Args:
        url (str): The URL to analyze.
    Returns:
        dict: A dictionary containing the analysis results.
    Raises:
        requests.exceptions.RequestException: If there's an error making the HTTP request.
    """
    try:
        response = requests.get(url, timeout=10)  # Add timeout to prevent hanging
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching URL: {e}")
        raise  # Re-raise the exception to be handled in main()

    headers = response.headers
    analysis_results = {}

    # Check for Strict-Transport-Security (HSTS)
    if "Strict-Transport-Security" not in headers:
        analysis_results["HSTS"] = "Missing Strict-Transport-Security header.  Vulnerable to man-in-the-middle attacks."
        logging.warning(f"Missing HSTS header for {url}")
    else:
        analysis_results["HSTS"] = "Strict-Transport-Security header found."
        logging.info(f"HSTS header found for {url}")

    # Check for X-Frame-Options
    if "X-Frame-Options" not in headers:
        analysis_results["X-Frame-Options"] = "Missing X-Frame-Options header. Vulnerable to clickjacking attacks."
        logging.warning(f"Missing X-Frame-Options header for {url}")
    else:
        analysis_results["X-Frame-Options"] = "X-Frame-Options header found."
        logging.info(f"X-Frame-Options header found for {url}")

    # Check for Content-Security-Policy (CSP)
    if "Content-Security-Policy" not in headers:
        analysis_results["CSP"] = "Missing Content-Security-Policy header. Vulnerable to cross-site scripting (XSS) attacks."
        logging.warning(f"Missing CSP header for {url}")
    else:
        analysis_results["CSP"] = "Content-Security-Policy header found."
        logging.info(f"CSP header found for {url}")

    # Check for X-Content-Type-Options
    if "X-Content-Type-Options" not in headers:
        analysis_results["X-Content-Type-Options"] = "Missing X-Content-Type-Options header. Vulnerable to MIME-sniffing attacks."
        logging.warning(f"Missing X-Content-Type-Options header for {url}")
    else:
        analysis_results["X-Content-Type-Options"] = "X-Content-Type-Options header found."
        logging.info(f"X-Content-Type-Options header found for {url}")

    # Check for Referrer-Policy
    if "Referrer-Policy" not in headers:
        analysis_results["Referrer-Policy"] = "Missing Referrer-Policy header.  May leak sensitive information in the Referer header."
        logging.warning(f"Missing Referrer-Policy header for {url}")
    else:
        analysis_results["Referrer-Policy"] = "Referrer-Policy header found."
        logging.info(f"Referrer-Policy header found for {url}")

    # Check for Permissions-Policy (formerly Feature-Policy)
    if "Permissions-Policy" not in headers and "Feature-Policy" not in headers:
        analysis_results["Permissions-Policy"] = "Missing Permissions-Policy (or Feature-Policy) header.  May allow unintended access to browser features."
        logging.warning(f"Missing Permissions-Policy/Feature-Policy header for {url}")
    else:
         policy_header = "Permissions-Policy" if "Permissions-Policy" in headers else "Feature-Policy"
         analysis_results["Permissions-Policy"] = f"{policy_header} header found."
         logging.info(f"{policy_header} header found for {url}")



    return analysis_results


def main():
    """
    Main function to parse arguments, analyze headers, and print results.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    url = args.url

    # Validate URL (basic check)
    if not url.startswith(("http://", "https://")):
        print("Error: URL must start with http:// or https://")
        sys.exit(1)

    try:
        analysis = analyze_headers(url)

        print(f"Security Analysis for {url}:\n")
        for header, result in analysis.items():
            print(f"{header}: {result}")

    except requests.exceptions.RequestException:
        print("An error occurred during the request. See logs for details.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        print("An unexpected error occurred. See logs for details.")
        sys.exit(1)


if __name__ == "__main__":
    # Example Usage:
    # To run: python main.py https://example.com
    # To run with verbose output: python main.py https://example.com -v
    main()