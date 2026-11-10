# vuln-Error-Message-Analyzer
Crawls a website and analyzes error messages for potentially sensitive information disclosure (e.g., database schema, internal paths, framework versions).

Verified behavior: the crawler follows same-host links up to the configured depth and analyzes error response bodies as primary targets, recording each page's HTTP status code in its findings. Script, style, and navigation blocks are removed before the page text is scanned, and the text is split into lines and sentences; a segment counts when it contains a keyword, whether or not it ends with sentence punctuation, so bare stack trace lines and short banners are included. Keywords are matched literally and case-insensitively, so regex characters in a keyword do not change its meaning. Secret shaped values in matched error text are redacted before the report is written, and severity is derived from the matched content: credential shaped disclosures rate Critical, database and schema disclosures rate High, other technical disclosures rate Medium, and generic keyword matches rate Low. An invalid start URL or a crawl that fetches no page writes a report carrying an explicit crawl failed status and exits non-zero.

## Install
`git clone https://github.com/ShadowGuard-AI/vuln-error-message-analyzer`

Then install the dependencies listed in requirements.txt: beautifulsoup4 and requests.

## Usage
`python main.py <url> [params]`

Example: `python main.py http://127.0.0.1:8080 --max-depth 2 --output report.txt`

## Parameters
- `-h`: Show help message and exit
- `--max-depth`: The maximum depth to crawl (default: 3).
- `--exclude`: List of URL patterns to exclude from crawling, for example /logout or /admin.
- `--keywords`: List of keywords to search for in error messages (default: error, exception, warning, debug, SQL, database, path, version).
- `--output`: The file to write the vulnerability report to (default: vulnerability_report.txt).

## License
MIT License. See the LICENSE file in this repository for the full text.
