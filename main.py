import argparse
import requests
import logging
import re
import sys
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

SECRET_PATTERNS = [
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9\-]{4,}\b", re.IGNORECASE),
    re.compile(r"\b(?:ghp|gho|github_pat|sk|pk)_[A-Za-z0-9_\-]{8,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.]{8,}", re.IGNORECASE),
    re.compile(r"\b(api[_-]?key|secret|token|password|passwd|credential)s?\b\s*[:=]\s*\S+", re.IGNORECASE),
]

def redact_secrets(text):
    """Replace secret shaped values with a redaction marker."""
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted

def contains_secret_shape(text):
    return any(pattern.search(text) for pattern in SECRET_PATTERNS)

def severity_for(message):
    """Rate a finding from its matched content."""
    lowered = message.lower()
    if contains_secret_shape(message) or "credential" in lowered or "api key" in lowered or "secret" in lowered:
        return "Critical"
    if any(word in lowered for word in ("database", "schema", "sql", "stack trace", "table ")):
        return "High"
    if any(word in lowered for word in ("exception", "debug", "version", "internal path")):
        return "Medium"
    return "Low"

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(
        description="Crawls a website and analyzes error messages for sensitive information disclosure."
    )
    parser.add_argument("url", help="The URL of the website to crawl.")
    parser.add_argument(
        "--max-depth",
        type=int,
        default=3,
        help="The maximum depth to crawl (default: 3).",
    )
    parser.add_argument(
        "--exclude",
        nargs="+",
        default=[],
        help="List of URL patterns to exclude from crawling (e.g., '/logout', '/admin').",
    )
    parser.add_argument(
        "--keywords",
        nargs="+",
        default=[
            "error",
            "exception",
            "warning",
            "debug",
            "SQL",
            "database",
            "path",
            "version",
        ],
        help="List of keywords to search for in error messages (default: error, exception, warning, debug, SQL, database, path, version).",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="vulnerability_report.txt",
        help="The file to write the vulnerability report to (default: vulnerability_report.txt).",
    )
    return parser


def is_valid_url(url):
    """
    Checks if a URL is valid.

    Args:
        url (str): The URL to check.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def crawl_website(url, max_depth, exclude, keywords, visited=None, depth=0, stats=None):
    """
    Crawls a website and analyzes error messages for sensitive information disclosure.

    Args:
        url (str): The URL of the website to crawl.
        max_depth (int): The maximum depth to crawl.
        exclude (list): A list of URL patterns to exclude from crawling.
        keywords (list): A list of keywords to search for in error messages.
        visited (set): A set of already visited URLs (for avoiding loops).
        depth (int): The current depth of the crawl.

    Returns:
        list: A list of dictionaries, where each dictionary represents a found vulnerability.
    """

    if visited is None:
        visited = set()
    if stats is None:
        stats = {"fetched": 0}

    if depth > max_depth or url in visited:
        return []

    visited.add(url)
    vulnerabilities = []

    try:
        logging.info(f"Crawling: {url} (Depth: {depth})")
        response = requests.get(url, timeout=10)
        # The body is analyzed before any status check: error responses
        # are the primary targets, and their status code is recorded in
        # each finding instead of the page being discarded.
        stats["fetched"] += 1
        status_code = response.status_code

        soup = BeautifulSoup(response.content, "html.parser")

        # Analyze error messages in the current page
        error_messages = analyze_error_messages(soup, keywords)
        for message in error_messages:
            severity = severity_for(message)
            safe_message = redact_secrets(message)
            vulnerabilities.append(
                {
                    "url": url,
                    "message": safe_message,
                    "status_code": status_code,
                    "severity": severity,
                    "description": f"Possible sensitive information disclosure in error message: {safe_message}",
                }
            )

        # Find all links on the page and crawl them recursively
        if depth < max_depth:
            for link in soup.find_all("a", href=True):
                absolute_url = urljoin(url, link["href"])

                # Normalize the URL to prevent duplicates due to trailing slashes, etc.
                absolute_url = absolute_url.rstrip("/")

                # Same host test: compare the parsed netloc of the
                # candidate against the parsed netloc of the base URL.
                if is_valid_url(absolute_url) and urlparse(absolute_url).netloc == urlparse(url).netloc:
                    is_excluded = False
                    for pattern in exclude:
                        if pattern in absolute_url:
                            is_excluded = True
                            break

                    if not is_excluded:
                        vulnerabilities.extend(
                            crawl_website(absolute_url, max_depth, exclude, keywords, visited, depth + 1, stats)
                        )


    except requests.exceptions.RequestException as e:
        logging.error(f"Error crawling {url}: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred while processing {url}: {e}")
    return vulnerabilities


def analyze_error_messages(soup, keywords):
    """
    Analyzes a BeautifulSoup object for error messages containing specified keywords.

    Args:
        soup (BeautifulSoup): The BeautifulSoup object representing the HTML content.
        keywords (list): A list of keywords to search for.

    Returns:
        list: A list of error messages containing the keywords.
    """
    error_messages = []
    # Drop script, style, and navigation blocks first, so their prose
    # is not scanned as if it were page body error text.
    try:
        for tag in soup.find_all(["script", "style", "nav", "header", "footer", "aside"]):
            tag.decompose()
    except Exception:
        pass
    try:
        text_content = soup.get_text(separator="\n")
    except TypeError:
        text_content = soup.get_text()
    # Split into lines and sentences. A segment does not need terminal
    # punctuation to count, so a bare stack trace line or a short
    # banner is scanned as well as a full sentence.
    segments = []
    for chunk in re.split(r"(?<=[.?!])\s+|\n+", text_content):
        chunk = chunk.strip()
        if chunk:
            segments.append(chunk)
    for keyword in keywords:
        if not keyword or not keyword.strip():
            continue
        # The keyword is escaped, so regex characters in it are matched
        # literally instead of changing the pattern or raising re.error.
        pattern = re.compile(re.escape(keyword.strip()), re.IGNORECASE)
        for segment in segments:
            if pattern.search(segment):
                error_messages.append(segment)
        # Remove duplicated messages, keeping order
        error_messages = list(dict.fromkeys(error_messages))

    return error_messages


def write_report(vulnerabilities, output_file, status=None):
    """
    Writes a vulnerability report to a file.

    Args:
        vulnerabilities (list): A list of dictionaries representing the vulnerabilities.
        output_file (str): The path to the output file.
        status (str): An explicit run status, for example a crawl failure,
            written into the report instead of a clean result.
    """
    try:
        with open(output_file, "w") as f:
            f.write("Vulnerability Report\n")
            f.write("--------------------\n\n")
            if status:
                f.write(f"Status: {status}\n\n")
            if not vulnerabilities:
                if not status:
                    f.write("No vulnerabilities found.\n")
            else:
                for vuln in vulnerabilities:
                    f.write(f"URL: {vuln['url']}\n")
                    if "status_code" in vuln:
                        f.write(f"Status Code: {vuln['status_code']}\n")
                    f.write(f"Severity: {vuln['severity']}\n")
                    f.write(f"Description: {redact_secrets(vuln['description'])}\n")
                    f.write(f"Error Message: {redact_secrets(vuln['message'])}\n")
                    f.write("\n")
        logging.info(f"Vulnerability report written to {output_file}")
    except IOError as e:
        logging.error(f"Error writing to report file: {e}")


def main():
    """
    The main function of the script.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    url = args.url
    max_depth = args.max_depth
    exclude = args.exclude
    keywords = args.keywords
    output_file = args.output

    # Input validation
    if not is_valid_url(url):
        print("Error: Invalid URL provided.")
        write_report([], output_file, status="Crawl failed: invalid start URL.")
        sys.exit(1)

    try:
        stats = {"fetched": 0}
        vulnerabilities = crawl_website(url, max_depth, exclude, keywords, stats=stats)
        if stats["fetched"] == 0:
            write_report(vulnerabilities, output_file, status="Crawl failed: no page could be fetched.")
            print(f"Crawl failed: no page could be fetched.  Check {output_file} for the status.")
            sys.exit(1)
        write_report(vulnerabilities, output_file)
        print(f"Analysis complete.  Check {output_file} for results.")

    except SystemExit:
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()