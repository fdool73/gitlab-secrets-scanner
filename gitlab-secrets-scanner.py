#!/usr/bin/env python3
"""
GitLab Secrets Scanner - Scans all repositories for secrets and builds a dashboard
Requires GitLab Ultimate license
"""

import os
import json
import argparse
import asyncio
import aiohttp
import pandas as pd
from datetime import datetime
from pathlib import Path
import webbrowser
from jinja2 import Template
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import print as rprint

class GitLabSecretsScanner:
    def __init__(self, output_dir="./results", include_subgroups=True, group=None):
        self.base_url = os.getenv('GITLAB_URL', 'https://git.hq.bill.com')
        self.token = os.getenv('GITLAB_TOKEN')
        
        if not self.token:
            raise ValueError("GITLAB_TOKEN environment variable must be set")
            
        self.headers = {'PRIVATE-TOKEN': self.token}
        self.output_dir = output_dir
        self.include_subgroups = include_subgroups
        self.group = group
        self.console = Console()
        self.secret_detection_historic_scan = os.getenv('SECRET_DETECTION_HISTORIC_SCAN', 'FALSE').upper() == 'TRUE'
        
        # Create output directory
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Initialize results storage
        self.all_projects = []
        self.scan_results = []
        self.vulnerability_reports = []
        
    async def get_all_projects(self, session):
        """Get all accessible projects"""
        self.console.print("[bold blue]Retrieving all accessible projects...[/bold blue]")
        
        all_projects = []
        page = 1
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]Fetching projects..."),
            BarColumn(),
            TextColumn("[bold]{task.completed} of {task.total}"),
            console=self.console
        ) as progress:
            # We don't know total pages yet, so start with an estimate
            task = progress.add_task("Fetching...", total=100)
            
            url_base = f"{self.base_url}/api/v4/projects?per_page=100&simple=true&membership=true&page="
            
            # Add group filter if specified
            if self.group:
                url_base = f"{self.base_url}/api/v4/groups/{self.group}/projects?per_page=100&simple=true&include_subgroups={str(self.include_subgroups).lower()}&page="
            
            while True:
                url = f"{url_base}{page}"
                
                try:
                    async with session.get(url, headers=self.headers) as response:
                        if response.status != 200:
                            self.console.print(f"[bold red]Error fetching projects: HTTP {response.status}[/bold red]")
                            break
                        
                        projects_page = await response.json()
                        if not projects_page:
                            break
                        
                        all_projects.extend(projects_page)
                        page += 1
                        
                        # Update progress
                        progress.update(task, completed=len(all_projects), 
                                       description=f"Found {len(all_projects)} projects...")
                        
                except Exception as e:
                    self.console.print(f"[bold red]Error fetching projects: {str(e)}[/bold red]")
                    break
            
            # Complete the progress bar
            progress.update(task, completed=100, total=100, 
                           description=f"Completed! Found {len(all_projects)} projects")
        
        self.console.print(f"[green]Found {len(all_projects)} projects[/green]")
        return all_projects
    
    async def trigger_security_scan(self, session, project):
        """Trigger a security scan for a project"""
        project_id = project['id']
        project_path = project['path_with_namespace']
        
        # Get security configuration
        url = f"{self.base_url}/api/v4/projects/{project_id}/security/configuration"
        
        try:
            async with session.get(url, headers=self.headers) as response:
                if response.status != 200:
                    return {
                        "project_id": project_id,
                        "project_name": project['name'],
                        "project_path": project_path,
                        "status": "error",
                        "error": f"HTTP {response.status}"
                    }
                
                config = await response.json()
                
                # Check if secret detection is available and enabled
                secret_detection = next((scan for scan in config.get("scan_execution_policy", []) 
                                        if scan.get("scan_type") == "secret_detection"), {})
                
                if not secret_detection:
                    return {
                        "project_id": project_id,
                        "project_name": project['name'],
                        "project_path": project_path,
                        "status": "unavailable",
                        "error": "Secret detection not available"
                    }
                
                if not secret_detection.get("enabled", False):
                    # Try to enable secret detection
                    enable_url = f"{self.base_url}/api/v4/projects/{project_id}/security/scan_execution_policies"
                    enable_data = {
                        "scan_type": "secret_detection",
                        "enabled": True
                    }
                    
                    async with session.post(enable_url, headers=self.headers, json=enable_data) as enable_response:
                        if enable_response.status not in [200, 201]:
                            return {
                                "project_id": project_id,
                                "project_name": project['name'],
                                "project_path": project_path,
                                "status": "disabled",
                                "error": "Failed to enable secret detection"
                            }
                
                # Trigger on-demand scan
                scan_url = f"{self.base_url}/api/v4/projects/{project_id}/security/scan"
                scan_data = {"scan_type": "secret_detection"}
                # Enable historic scan if configured
                if self.secret_detection_historic_scan:
                    scan_data["historic_scan"] = True

                async with session.post(scan_url, headers=self.headers, json=scan_data) as scan_response:
                    if scan_response.status != 201:
                        return {
                            "project_id": project_id,
                            "project_name": project['name'],
                            "project_path": project_path,
                            "status": "failed",
                            "error": f"Failed to start scan: HTTP {scan_response.status}"
                        }
                    
                    scan_result = await scan_response.json()
                    scan_id = scan_result.get("id")
                    
                    return {
                        "project_id": project_id,
                        "project_name": project['name'],
                        "project_path": project_path,
                        "status": "triggered",
                        "scan_id": scan_id
                    }
                    
        except Exception as e:
            return {
                "project_id": project_id,
                "project_name": project['name'],
                "project_path": project_path,
                "status": "error",
                "error": str(e)
            }
    
    async def get_vulnerability_report(self, session, project):
        """Get vulnerability report for a project"""
        project_id = project['id']
        project_path = project['path_with_namespace']
        
        url = f"{self.base_url}/api/v4/projects/{project_id}/vulnerability_findings?scope=all&scanner=secret_detection"
        
        try:
            async with session.get(url, headers=self.headers) as response:
                if response.status != 200:
                    return {
                        "project_id": project_id,
                        "project_name": project['name'],
                        "project_path": project_path,
                        "vulnerabilities": [],
                        "status": "error",
                        "error": f"HTTP {response.status}"
                    }
                
                vulnerabilities = await response.json()
                
                # Enrich vulnerability data with additional info
                for vuln in vulnerabilities:
                    # Add project context
                    vuln["project_id"] = project_id
                    vuln["project_name"] = project['name']
                    vuln["project_path"] = project_path
                    
                    # Add direct link to vulnerability
                    if 'id' in vuln:
                        vuln["url"] = f"{self.base_url}/{project_path}"
                    
                return {
                    "project_id": project_id,
                    "project_name": project['name'],
                    "project_path": project_path,
                    "vulnerabilities": vulnerabilities,
                    "status": "success"
                }
                
        except Exception as e:
            return {
                "project_id": project_id,
                "project_name": project['name'],
                "project_path": project_path,
                "vulnerabilities": [],
                "status": "error",
                "error": str(e)
            }
    
    async def scan_all_projects(self):
        """Scan all projects for secrets"""
        self.console.print("[bold blue]Starting GitLab Secrets Scanner...[/bold blue]")
        
        # Create aiohttp session
        async with aiohttp.ClientSession() as session:
            # Get all projects
            self.all_projects = await self.get_all_projects(session)
            
            if not self.all_projects:
                self.console.print("[bold red]No projects found. Exiting.[/bold red]")
                return False
            
            # Trigger scans
            self.console.print("[bold blue]Triggering secret detection scans...[/bold blue]")
            
            scan_tasks = []
            concurrency_limit = asyncio.Semaphore(10)  # Limit concurrent requests
            
            async def bounded_scan(project):
                async with concurrency_limit:
                    return await self.trigger_security_scan(session, project)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Triggering scans..."),
                BarColumn(),
                TextColumn("[bold]{task.completed}/{task.total}"),
                console=self.console
            ) as progress:
                scan_progress = progress.add_task("Scanning...", total=len(self.all_projects))
                
                for project in self.all_projects:
                    task = asyncio.create_task(bounded_scan(project))
                    task.add_done_callback(
                        lambda t, p=progress, task_id=scan_progress: p.update(task_id, advance=1)
                    )
                    scan_tasks.append(task)
                
                # Wait for all scans to complete
                self.scan_results = await asyncio.gather(*scan_tasks)
            
            # Save scan trigger results
            with open(f"{self.output_dir}/scan_triggers.json", 'w') as f:
                json.dump(self.scan_results, f, indent=2)
            
            # Count successful scans
            successful_scans = sum(1 for r in self.scan_results if r['status'] == 'triggered')
            self.console.print(f"[green]Successfully triggered {successful_scans} out of {len(self.scan_results)} scans[/green]")
            
            # Wait for scans to complete
            wait_time = 120  # seconds
            self.console.print(f"[bold blue]Waiting {wait_time} seconds for scans to complete...[/bold blue]")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Waiting for scans to complete..."),
                BarColumn(),
                TextColumn("{task.percentage:.0f}%"),
                console=self.console
            ) as progress:
                wait_task = progress.add_task("Waiting...", total=wait_time)
                for i in range(wait_time):
                    await asyncio.sleep(1)
                    progress.update(wait_task, advance=1)
            
            # Get vulnerability reports
            self.console.print("[bold blue]Collecting vulnerability reports...[/bold blue]")
            
            vuln_tasks = []
            
            async def bounded_vuln_scan(project):
                async with concurrency_limit:
                    return await self.get_vulnerability_report(session, project)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Collecting reports..."),
                BarColumn(),
                TextColumn("[bold]{task.completed}/{task.total}"),
                console=self.console
            ) as progress:
                vuln_progress = progress.add_task("Collecting...", total=len(self.all_projects))
                
                for project in self.all_projects:
                    task = asyncio.create_task(bounded_vuln_scan(project))
                    task.add_done_callback(
                        lambda t, p=progress, task_id=vuln_progress: p.update(task_id, advance=1)
                    )
                    vuln_tasks.append(task)
                
                # Wait for all vulnerability reports to complete
                self.vulnerability_reports = await asyncio.gather(*vuln_tasks)
            
            # Save vulnerability reports
            with open(f"{self.output_dir}/vulnerability_reports.json", 'w') as f:
                json.dump(self.vulnerability_reports, f, indent=2)
            
            return True
    
    def generate_dashboard(self):
        """Generate HTML dashboard from vulnerability reports"""
        self.console.print("[bold blue]Generating dashboard...[/bold blue]")
        
        # Process data for dashboard
        all_vulnerabilities = []
        for report in self.vulnerability_reports:
            for vuln in report.get("vulnerabilities", []):
                # Core vulnerability data is already enriched with project info
                all_vulnerabilities.append(vuln)
        
        # Create a DataFrame for analysis
        if all_vulnerabilities:
            df = pd.DataFrame(all_vulnerabilities)
            
            # Generate summary statistics
            projects_with_secrets = df["project_id"].nunique()
            total_projects = len(self.all_projects)
            total_secrets = len(df)
            
            # Get counts by severity
            if 'severity' in df.columns:
                secrets_by_severity = df["severity"].value_counts().to_dict()
            else:
                secrets_by_severity = {}
                
            # Get counts by project
            if 'project_name' in df.columns:
                secrets_by_project = df.groupby("project_name").size().sort_values(ascending=False).to_dict()
            else:
                secrets_by_project = {}
                
            # Get top secret types
            if 'name' in df.columns:
                top_secret_types = df["name"].value_counts().head(10).to_dict()
            else:
                top_secret_types = {}
        else:
            # No vulnerabilities found
            projects_with_secrets = 0
            total_projects = len(self.all_projects)
            total_secrets = 0
            secrets_by_severity = {}
            secrets_by_project = {}
            top_secret_types = {}
            
            # Create empty DataFrame for consistency
            df = pd.DataFrame(columns=["project_id", "project_name", "name", "severity", "description", "location", "id", "url"])
        
        # Create data summary tables
        severity_table = Table(title="Secrets by Severity", show_header=True)
        severity_table.add_column("Severity")
        severity_table.add_column("Count", justify="right")
        
        for severity, count in secrets_by_severity.items():
            color = "green"
            if severity == "critical":
                color = "red"
            elif severity == "high":
                color = "orange3"
            elif severity == "medium":
                color = "yellow"
                
            severity_table.add_row(severity, f"[{color}]{count}[/{color}]")
        
        self.console.print(severity_table)
        
        # Dashboard HTML template
        html_template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>GitLab Secrets Scanner Dashboard</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                .dashboard-card {
                    border-radius: 10px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                    margin-bottom: 20px;
                }
                .severity-critical { background-color: #ff5252; color: white; }
                .severity-high { background-color: #ff9100; color: white; }
                .severity-medium { background-color: #ffb74d; color: black; }
                .severity-low { background-color: #ffee58; color: black; }
                .severity-info { background-color: #b2dfdb; color: black; }
                .severity-unknown { background-color: #e0e0e0; color: black; }
                
                .table-hover tbody tr:hover {
                    background-color: rgba(0, 0, 0, 0.05);
                }
                
                .summary-number {
                    font-size: 2.5rem;
                    font-weight: bold;
                    text-align: center;
                }
                
                .summary-label {
                    text-align: center;
                    font-size: 0.9rem;
                    color: #6c757d;
                }
                
                .status-badge {
                    display: inline-block;
                    padding: 0.35em 0.65em;
                    font-size: 0.75em;
                    font-weight: 700;
                    line-height: 1;
                    color: #fff;
                    text-align: center;
                    white-space: nowrap;
                    vertical-align: baseline;
                    border-radius: 0.25rem;
                }
                
                .file-path {
                    max-width: 200px;
                    white-space: nowrap;
                    overflow: hidden;
                    text-overflow: ellipsis;
                }
            </style>
        </head>
        <body>
            <div class="container-fluid p-4">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h1>GitLab Secrets Scanner Dashboard</h1>
                    <span class="text-muted">Scan completed: {{ scan_date }}</span>
                </div>
                
                <div class="row">
                    <div class="col-md-4">
                        <div class="card dashboard-card">
                            <div class="card-body">
                                <div class="summary-number">{{ total_secrets }}</div>
                                <div class="summary-label">Total Secrets Found</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-4">
                        <div class="card dashboard-card">
                            <div class="card-body">
                                <div class="summary-number">{{ projects_with_secrets }}</div>
                                <div class="summary-label">Projects with Secrets</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-4">
                        <div class="card dashboard-card">
                            <div class="card-body">
                                <div class="summary-number">{{ total_projects }}</div>
                                <div class="summary-label">Total Projects Scanned</div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="row mt-4">
                    <div class="col-md-6">
                        <div class="card dashboard-card">
                            <div class="card-body">
                                <h5 class="card-title">Secrets by Severity</h5>
                                <canvas id="severityChart"></canvas>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="card dashboard-card">
                            <div class="card-body">
                                <h5 class="card-title">Top Secret Types</h5>
                                <canvas id="secretTypesChart"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="row mt-4">
                    <div class="col-12">
                        <div class="card dashboard-card">
                            <div class="card-body">
                                <h5 class="card-title">Projects with Most Secrets</h5>
                                <canvas id="projectsChart" style="height: 300px;"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="row mt-4">
                    <div class="col-12">
                        <div class="card dashboard-card">
                            <div class="card-header bg-light">
                                <div class="d-flex justify-content-between align-items-center">
                                    <h5 class="mb-0">All Detected Secrets</h5>
                                    <input type="text" id="secretSearch" class="form-control form-control-sm w-25" placeholder="Search...">
                                </div>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-striped table-hover" id="secretsTable">
                                        <thead>
                                            <tr>
                                                <th>Project</th>
                                                <th>Secret Type</th>
                                                <th>Severity</th>
                                                <th>File</th>
                                                <th>Line</th>
                                                <th>Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {% for vuln in vulnerabilities %}
                                            <tr>
                                                <td>{{ vuln.project_name }}</td>
                                                <td>{{ vuln.name }}</td>
                                                <td>
                                                    <span class="status-badge severity-{{ vuln.severity|lower }}">
                                                        {{ vuln.severity }}
                                                    </span>
                                                </td>
                                                <td class="file-path" title="{{ vuln.location.file }}">{{ vuln.location.file }}</td>
                                                <td>{{ vuln.location.start_line }}</td>
                                                <td>
                                                    <a href="{{ vuln.url }}" target="_blank" class="btn btn-sm btn-primary">View</a>
                                                </td>
                                            </tr>
                                            {% endfor %}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <script>
                // Charts
                document.addEventListener('DOMContentLoaded', function() {
                    // Severity chart
                    const severityCtx = document.getElementById('severityChart').getContext('2d');
                    new Chart(severityCtx, {
                        type: 'pie',
                        data: {
                            labels: {{ severity_labels|safe }},
                            datasets: [{
                                data: {{ severity_data }},
                                backgroundColor: [
                                    '#ff5252', // critical
                                    '#ff9100', // high
                                    '#ffb74d', // medium
                                    '#ffee58', // low
                                    '#b2dfdb', // info
                                    '#e0e0e0'  // unknown
                                ]
                            }]
                        },
                        options: {
                            responsive: true,
                            plugins: {
                                legend: {
                                    position: 'right'
                                }
                            }
                        }
                    });
                    
                    // Secret types chart
                    const typesCtx = document.getElementById('secretTypesChart').getContext('2d');
                    new Chart(typesCtx, {
                        type: 'doughnut',
                        data: {
                            labels: {{ secret_types_labels|safe }},
                            datasets: [{
                                data: {{ secret_types_data }},
                                backgroundColor: [
                                    '#3f51b5', '#2196f3', '#03a9f4', '#00bcd4', 
                                    '#009688', '#4caf50', '#8bc34a', '#cddc39', 
                                    '#ffeb3b', '#ffc107'
                                ]
                            }]
                        },
                        options: {
                            responsive: true,
                            plugins: {
                                legend: {
                                    position: 'right'
                                }
                            }
                        }
                    });
                    
                    // Projects chart
                    const projectsCtx = document.getElementById('projectsChart').getContext('2d');
                    new Chart(projectsCtx, {
                        type: 'bar',
                        data: {
                            labels: {{ projects_labels|safe }},
                            datasets: [{
                                label: 'Number of Secrets',
                                data: {{ projects_data }},
                                backgroundColor: '#2196f3'
                            }]
                        },
                        options: {
                            responsive: true,
                            indexAxis: 'y',
                            plugins: {
                                legend: {
                                    display: false
                                }
                            }
                        }
                    });
                    
                    // Search functionality
                    const searchInput = document.getElementById('secretSearch');
                    const table = document.getElementById('secretsTable');
                    const rows = table.getElementsByTagName('tr');
                    
                    searchInput.addEventListener('keyup', function() {
                        const query = searchInput.value.toLowerCase();
                        
                        for (let i = 1; i < rows.length; i++) {
                            let found = false;
                            const cells = rows[i].getElementsByTagName('td');
                            
                            for (let j = 0; j < cells.length; j++) {
                                const cellText = cells[j].textContent.toLowerCase();
                                
                                if (cellText.indexOf(query) > -1) {
                                    found = true;
                                    break;
                                }
                            }
                            
                            if (found) {
                                rows[i].style.display = '';
                            } else {
                                rows[i].style.display = 'none';
                            }
                        }
                    });
                });
            </script>
        </body>
        </html>
        """
        
        # Prepare data for charts
        severity_labels = list(secrets_by_severity.keys())
        severity_data = list(secrets_by_severity.values())
        
        secret_types_labels = list(top_secret_types.keys())
        secret_types_data = list(top_secret_types.values())
        
        # Limit to top 15 projects for the chart
        top_projects = dict(list(secrets_by_project.items())[:15])
        projects_labels = list(top_projects.keys())
        projects_data = list(top_projects.values())
        
        # Convert empty arrays to at least contain one item to avoid Chart.js errors
        if not severity_labels:
            severity_labels = ["No data"]
            severity_data = [1]
            
        if not secret_types_labels:
            secret_types_labels = ["No data"]
            secret_types_data = [1]
            
        if not projects_labels:
            projects_labels = ["No data"]
            projects_data = [0]
        
        # Render template
        template = Template(html_template)
        html_content = template.render(
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_projects=total_projects,
            projects_with_secrets=projects_with_secrets,
            total_secrets=total_secrets,
            vulnerabilities=all_vulnerabilities,
            severity_labels=json.dumps(severity_labels),
            severity_data=severity_data,
            secret_types_labels=json.dumps(secret_types_labels),
            secret_types_data=secret_types_data,
            projects_labels=json.dumps(projects_labels),
            projects_data=projects_data
        )
        
        # Save dashboard
        dashboard_path = f"{self.output_dir}/dashboard.html"
        with open(dashboard_path, 'w') as f:
            f.write(html_content)
        
        self.console.print(f"[green]Dashboard generated: {dashboard_path}[/green]")
        return dashboard_path
        
    def export_csv_report(self):
        """Export vulnerability data to CSV"""
        # Process all vulnerabilities
        all_vulnerabilities = []
        for report in self.vulnerability_reports:
            for vuln in report.get("vulnerabilities", []):
                # Create a flattened representation for CSV
                flat_vuln = {
                    "project_id": vuln.get("project_id"),
                    "project_name": vuln.get("project_name"),
                    "project_path": vuln.get("project_path"),
                    "name": vuln.get("name"),
                    "description": vuln.get("description", ""),
                    "severity": vuln.get("severity", "unknown"),
                    "confidence": vuln.get("confidence", "unknown"),
                    "file": vuln.get("location", {}).get("file", ""),
                    "line": vuln.get("location", {}).get("start_line", ""),
                    "scanner": vuln.get("scanner", {}).get("name", ""),
                    "url": vuln.get("url", "")
                }
                all_vulnerabilities.append(flat_vuln)
        
        if all_vulnerabilities:
            # Convert to DataFrame
            df = pd.DataFrame(all_vulnerabilities)
            
            # Save to CSV
            csv_path = f"{self.output_dir}/secrets_report.csv"
            df.to_csv(csv_path, index=False)
            self.console.print(f"[green]CSV report generated: {csv_path}[/green]")
            return csv_path
        else:
            self.console.print("[yellow]No vulnerabilities found, CSV report not generated[/yellow]")
            return None

async def run_scanner(args):
    try:
        scanner = GitLabSecretsScanner(
            output_dir=args.output,
            include_subgroups=args.include_subgroups,
            group=args.group
        )
        
        success = await scanner.scan_all_projects()
        
        if success:
            dashboard_path = scanner.generate_dashboard()
            csv_path = scanner.export_csv_report()
            
            if args.open_dashboard and dashboard_path:
                webbrowser.open(f"file://{os.path.abspath(dashboard_path)}")
                
            return 0
        
        return 1
        
    except Exception as e:
        Console().print(f"[bold red]Error: {str(e)}[/bold red]")
        return 1

def main():
    parser = argparse.ArgumentParser(description='GitLab Secrets Scanner - Scans all repositories for secrets')
    parser.add_argument('--output', default='./results', help='Output directory for results')
    parser.add_argument('--open-dashboard', action='store_true', help='Open dashboard in browser when finished')
    parser.add_argument('--group', help='Limit scanning to repositories in a specific group')
    parser.add_argument('--include-subgroups', action='store_true', default=True, help='Include subgroups when specified with --group')
    args = parser.parse_args()
    
    # Check for environment variables
    if not os.getenv('GITLAB_TOKEN'):
        print("Error: GITLAB_TOKEN environment variable must be set")
        print("Example: export GITLAB_TOKEN=your_personal_access_token")
        return 1
        
    if not os.getenv('GITLAB_URL'):
        print("Warning: GITLAB_URL environment variable not set, using default: https://gitlab.com")
        print("To set custom GitLab instance: export GITLAB_URL=https://your-gitlab-instance.com")
    
    # Run the scanner
    return asyncio.run(run_scanner(args))

if __name__ == "__main__":
    exit(main())
