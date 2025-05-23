import argparse
import requests
import logging
import re
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

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


def crawl_website(url, max_depth, exclude, keywords, visited=None, depth=0):
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

    if depth > max_depth or url in visited:
        return []

    visited.add(url)
    vulnerabilities = []

    try:
        logging.info(f"Crawling: {url} (Depth: {depth})")
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        soup = BeautifulSoup(response.content, "html.parser")

        # Analyze error messages in the current page
        error_messages = analyze_error_messages(soup, keywords)
        for message in error_messages:
            vulnerabilities.append(
                {
                    "url": url,
                    "message": message,
                    "severity": "Medium", # Heuristic value, refine based on message content
                    "description": f"Possible sensitive information disclosure in error message: {message}",
                }
            )

        # Find all links on the page and crawl them recursively
        if depth < max_depth:
            for link in soup.find_all("a", href=True):
                absolute_url = urljoin(url, link["href"])

                # Normalize the URL to prevent duplicates due to trailing slashes, etc.
                absolute_url = absolute_url.rstrip("/")

                if is_valid_url(absolute_url) and absolute_url.startswith(urlparse(url).netloc):
                    is_excluded = False
                    for pattern in exclude:
                        if pattern in absolute_url:
                            is_excluded = True
                            break

                    if not is_excluded:
                        vulnerabilities.extend(
                            crawl_website(absolute_url, max_depth, exclude, keywords, visited, depth + 1)
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
    text_content = soup.get_text().lower() # Convert to lowercase for case-insensitive search
    for keyword in keywords:
        if keyword.lower() in text_content: #Case insensitive check
            # Very basic implementation.  Consider improving with regex and context extraction.
            matches = re.findall(r"[^.?!]*(?:" + keyword.lower() + r")[^.?!]*[.?!]", text_content)
            error_messages.extend(matches)
            #Remove duplicated messages, keeping order
            error_messages = list(dict.fromkeys(error_messages))

    return error_messages


def write_report(vulnerabilities, output_file):
    """
    Writes a vulnerability report to a file.

    Args:
        vulnerabilities (list): A list of dictionaries representing the vulnerabilities.
        output_file (str): The path to the output file.
    """
    try:
        with open(output_file, "w") as f:
            f.write("Vulnerability Report\n")
            f.write("--------------------\n\n")
            if not vulnerabilities:
                f.write("No vulnerabilities found.\n")
            else:
                for vuln in vulnerabilities:
                    f.write(f"URL: {vuln['url']}\n")
                    f.write(f"Severity: {vuln['severity']}\n")
                    f.write(f"Description: {vuln['description']}\n")
                    f.write(f"Error Message: {vuln['message']}\n")
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
        return

    try:
        vulnerabilities = crawl_website(url, max_depth, exclude, keywords)
        write_report(vulnerabilities, output_file)
        print(f"Analysis complete.  Check {output_file} for results.")

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()