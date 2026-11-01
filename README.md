# vuln-Error-Message-Analyzer
Crawls a website and analyzes error messages for potentially sensitive information disclosure (e.g., database schema, internal paths, framework versions). - Focused on Assess vulnerabilities in web applications by performing scans and providing detailed reports

The crawler follows same-host links up to the configured depth and analyzes error response bodies as primary targets, recording each page's HTTP status code in its findings. Secret shaped values in matched error text are redacted before the report is written, and severity is derived from the matched content: credential shaped disclosures rate Critical, database and schema disclosures rate High, other technical disclosures rate Medium, and generic keyword matches rate Low. An invalid start URL or a crawl that fetches no page writes a report carrying an explicit crawl failed status and exits non-zero.

## Install
`git clone https://github.com/ShadowStrikeHQ/vuln-error-message-analyzer`

## Usage
`./vuln-error-message-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `--max-depth`: No description provided
- `--exclude`: List of URL patterns to exclude from crawling (e.g., 
- `--keywords`: No description provided
- `--output`: No description provided

## License
Copyright (c) ShadowStrikeHQ
