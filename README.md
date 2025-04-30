# GitLab Secrets Scanner

An asynchronous scanner for detecting secrets and credentials accidentally committed to GitLab repositories. This tool leverages GitLab's native security APIs to perform comprehensive secret detection across all our repositories.

## Features

- **Comprehensive Scanning**: Detects passwords, API keys, tokens, and other secrets in your code
- **Async Processing**: Uses async I/O for efficient concurrent scanning of multiple repositories
- **Group Filtering**: Option to scan specific groups and their subgroups
- **Interactive Dashboard**: HTML dashboard with charts and filtering capabilities
- **CSV Export**: Export findings to CSV for further analysis or reporting
- **Rich Console Output**: Detailed terminal output with progress indicators
- **GitLab Ultimate Integration**: Leverages GitLab's built-in security scanning capabilities

## Requirements

- Python 3.7+
- GitLab Ultimate license
- Personal access token with API scope

## Installation

1. Clone this repository:
   ```bash
   git clone https://your-repo-url/gitlab_secrets_scanner.git
   cd gitlab_secrets_scanner
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

The scanner uses environment variables for configuration:

- `GITLAB_URL`: Your GitLab instance URL (default: https://gitlab.com)
- `GITLAB_TOKEN`: Your GitLab personal access token with API scope

Set these environment variables before running the scanner:

```bash
export GITLAB_URL=https://your-gitlab-instance.com
export GITLAB_TOKEN=your_personal_access_token
```

## Usage

### Basic Usage

Run the scanner against all repositories you have access to:

```bash
python gitlab_secrets_scanner.py
```

### Scan a Specific Group

To scan only repositories within a specific group:

```bash
python gitlab_secrets_scanner.py --group your-group-name
```

### Include Subgroups

By default, subgroups are included when scanning a group. To explicitly include subgroups:

```bash
python gitlab_secrets_scanner.py --group your-group-name --include-subgroups
```

### Custom Output Directory

Specify a custom directory for output files:

```bash
python gitlab_secrets_scanner.py --output ./my-scan-results
```

### Open Dashboard Automatically

Automatically open the dashboard in your browser when scanning completes:

```bash
python gitlab_secrets_scanner.py --open-dashboard
```

## Output Files

The scanner generates several output files in the specified output directory (default: `./results`):

- `dashboard.html`: Interactive HTML dashboard with charts and details
- `secrets_report.csv`: CSV report of all found secrets for importing into other tools
- `scan_triggers.json`: Raw JSON data about triggered scans
- `vulnerability_reports.json`: Raw JSON data of all vulnerabilities found

## Understanding the Dashboard

The HTML dashboard provides several visualizations and summaries:

1. **Summary Statistics**: Total secrets found, affected projects, and total scanned projects
2. **Severity Distribution**: Pie chart showing the distribution of secrets by severity
3. **Secret Types**: Breakdown of the different types of secrets found
4. **Projects Ranking**: Bar chart showing projects with the most secrets
5. **Detailed Table**: Searchable table with all detected secrets, including:
   - Project name
   - Secret type
   - Severity
   - File location
   - Line number
   - Link to view the secret in GitLab

## How It Works

1. The scanner authenticates with GitLab using your personal access token
2. It retrieves a list of all accessible projects
3. For each project, it:
   - Checks if secret detection is available
   - Enables it if necessary (and possible)
   - Triggers an on-demand secret detection scan
4. After allowing time for scans to complete, it collects all vulnerability reports
5. Finally, it processes the results and generates an interactive dashboard

## Troubleshooting

### Common Issues

- **Authentication Errors**: Ensure your `GITLAB_TOKEN` has the API scope and hasn't expired
- **Permission Errors**: Verify you have permissions to access the repositories being scanned
- **No Secrets Found**: Confirm you're using GitLab Ultimate (required for secret detection)
- **Rate Limiting**: If encountering GitLab API rate limits, increase wait times between requests

### Debug Output

For more detailed logging, modify the script to increase the verbosity level of the console output.

## Acknowledgements

This tool leverages GitLab's built-in security scanning capabilities and is designed to work with GitLab Ultimate.
