#!/usr/bin/env python3
"""
Watchtower - Batch Scanner for Contract Target Radar

This script processes a CSV file from the "Contract Target Radar" and runs automated
security audits using Hound for each new or updated repository.

Usage:
    python scripts/watchtower.py <radar_csv> [--output-dir <path>] [--filter <status>]

Example:
    python scripts/watchtower.py radar_output.csv --output-dir ./audit_results --filter NEW,UPDATED
"""

import argparse
import csv
import json
import logging
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('watchtower.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class WatchtowerScanner:
    """Batch scanner for processing repositories from Contract Target Radar."""
    
    def __init__(self, csv_path: str, output_dir: str = "./watchtower_output", 
                 filter_status: Optional[List[str]] = None):
        """
        Initialize the Watchtower scanner.
        
        Args:
            csv_path: Path to the Radar CSV file
            output_dir: Directory to store audit results
            filter_status: List of status values to filter (e.g., ['NEW', 'UPDATED'])
        """
        self.csv_path = Path(csv_path)
        self.output_dir = Path(output_dir)
        self.filter_status = [s.upper() for s in filter_status] if filter_status else ['NEW', 'UPDATED']
        self.temp_workspace = Path("./watchtower_temp")
        self.hound_script = Path(__file__).parent.parent / "hound.py"
        
        # Ensure output directories exist
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.temp_workspace.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Initialized Watchtower Scanner")
        logger.info(f"  CSV: {self.csv_path}")
        logger.info(f"  Output: {self.output_dir}")
        logger.info(f"  Filter: {self.filter_status}")
        logger.info(f"  Hound: {self.hound_script}")
    
    def parse_csv(self) -> List[Dict[str, str]]:
        """
        Parse the Radar CSV file and filter repositories.
        
        Returns:
            List of repository dictionaries with keys: org, repo, status, url, etc.
        """
        if not self.csv_path.exists():
            raise FileNotFoundError(f"CSV file not found: {self.csv_path}")
        
        repos = []
        with open(self.csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            # Normalize headers to lowercase for case-insensitive matching
            headers = [h.lower().strip() for h in reader.fieldnames or []]
            logger.info(f"CSV headers: {headers}")
            
            for row_num, row in enumerate(reader, start=2):
                # Normalize keys to lowercase
                normalized_row = {k.lower().strip(): v.strip() for k, v in row.items()}
                
                # Extract key fields (handle various possible column names)
                status = normalized_row.get('status', '').upper()
                repo_url = normalized_row.get('url', '') or normalized_row.get('repo_url', '') or normalized_row.get('repository', '')
                org = normalized_row.get('org', '') or normalized_row.get('organization', '')
                repo_name = normalized_row.get('repo', '') or normalized_row.get('repo_name', '') or normalized_row.get('name', '')
                
                # Skip if status doesn't match filter
                if status not in self.filter_status:
                    logger.debug(f"Row {row_num}: Skipping (status={status}, not in filter)")
                    continue
                
                # Skip if required fields are missing
                if not repo_url:
                    logger.warning(f"Row {row_num}: Missing repository URL, skipping")
                    continue
                
                # Infer org and repo name from URL if not provided
                if not org or not repo_name:
                    try:
                        # Parse GitHub URL: https://github.com/org/repo
                        url_parts = repo_url.rstrip('/').split('/')
                        if len(url_parts) >= 2:
                            inferred_org = url_parts[-2]
                            inferred_repo = url_parts[-1].replace('.git', '')
                            org = org or inferred_org
                            repo_name = repo_name or inferred_repo
                    except Exception as e:
                        logger.warning(f"Row {row_num}: Could not parse org/repo from URL: {e}")
                
                if not org or not repo_name:
                    logger.warning(f"Row {row_num}: Could not determine org/repo, skipping")
                    continue
                
                repo_info = {
                    'org': org,
                    'repo': repo_name,
                    'status': status,
                    'url': repo_url,
                    'row_num': row_num,
                    'raw_data': normalized_row
                }
                repos.append(repo_info)
                logger.info(f"Row {row_num}: Added {org}/{repo_name} (status={status})")
        
        logger.info(f"Parsed {len(repos)} repositories from CSV")
        return repos
    
    def clone_repository(self, repo_url: str, target_dir: Path) -> bool:
        """
        Clone a git repository to the target directory.
        
        Args:
            repo_url: Git repository URL
            target_dir: Directory to clone into
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Remove existing directory if present
            if target_dir.exists():
                logger.info(f"Removing existing directory: {target_dir}")
                shutil.rmtree(target_dir)
            
            logger.info(f"Cloning repository: {repo_url}")
            result = subprocess.run(
                ['git', 'clone', '--depth', '1', repo_url, str(target_dir)],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                logger.error(f"Git clone failed: {result.stderr}")
                return False
            
            logger.info(f"Successfully cloned to: {target_dir}")
            return True
            
        except subprocess.TimeoutExpired:
            logger.error(f"Git clone timed out after 5 minutes")
            return False
        except Exception as e:
            logger.error(f"Error cloning repository: {e}")
            return False
    
    def create_hound_project(self, project_name: str, source_path: Path) -> bool:
        """
        Create a Hound project for the repository.
        
        Args:
            project_name: Name for the Hound project
            source_path: Path to the source code
            
        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"Creating Hound project: {project_name}")
            result = subprocess.run(
                [sys.executable, str(self.hound_script), 'project', 'create', 
                 project_name, str(source_path)],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                logger.error(f"Project creation failed: {result.stderr}")
                return False
            
            logger.info(f"Successfully created project: {project_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error creating project: {e}")
            return False
    
    def run_audit(self, project_name: str, iterations: int = 30) -> bool:
        """
        Run a Hound audit on the project using headless mode.
        
        Args:
            project_name: Name of the Hound project
            iterations: Maximum iterations for the audit
            
        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"Running audit on project: {project_name} (iterations={iterations})")
            
            # Run in headless mode for automated execution
            result = subprocess.run(
                [sys.executable, str(self.hound_script), 'agent', 'audit',
                 '--project', project_name,
                 '--iterations', str(iterations),
                 '--headless'],
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            if result.returncode != 0:
                logger.error(f"Audit failed: {result.stderr}")
                logger.error(f"Stdout: {result.stdout}")
                return False
            
            logger.info(f"Successfully completed audit for: {project_name}")
            logger.debug(f"Audit output: {result.stdout}")
            return True
            
        except subprocess.TimeoutExpired:
            logger.error(f"Audit timed out after 1 hour")
            return False
        except Exception as e:
            logger.error(f"Error running audit: {e}")
            return False
    
    def generate_report(self, project_name: str, output_path: Path) -> bool:
        """
        Generate a Hound report for the project.
        
        Args:
            project_name: Name of the Hound project
            output_path: Path to save the report
            
        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"Generating report for: {project_name}")
            
            result = subprocess.run(
                [sys.executable, str(self.hound_script), 'report',
                 project_name,
                 '--output', str(output_path),
                 '--format', 'html'],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                logger.error(f"Report generation failed: {result.stderr}")
                return False
            
            logger.info(f"Successfully generated report: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return False
    
    def process_repository(self, repo_info: Dict[str, str]) -> bool:
        """
        Process a single repository through the complete audit pipeline.
        
        Args:
            repo_info: Repository information dictionary
            
        Returns:
            True if successful, False otherwise
        """
        org = repo_info['org']
        repo = repo_info['repo']
        url = repo_info['url']
        
        logger.info(f"\n{'='*80}")
        logger.info(f"Processing: {org}/{repo}")
        logger.info(f"{'='*80}")
        
        # Create unique project name
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        project_name = f"{org}_{repo}_{timestamp}".replace('/', '_').replace('-', '_')
        
        # Setup paths
        clone_dir = self.temp_workspace / f"{org}_{repo}"
        output_subdir = self.output_dir / org / repo / datetime.now().strftime("%Y-%m-%d")
        output_subdir.mkdir(parents=True, exist_ok=True)
        report_path = output_subdir / "audit_report.html"
        
        # Save repository info
        info_path = output_subdir / "repo_info.json"
        with open(info_path, 'w') as f:
            json.dump(repo_info, f, indent=2)
        
        try:
            # Step 1: Clone repository
            if not self.clone_repository(url, clone_dir):
                logger.error(f"Failed to clone {org}/{repo}")
                return False
            
            # Step 2: Create Hound project
            if not self.create_hound_project(project_name, clone_dir):
                logger.error(f"Failed to create project for {org}/{repo}")
                return False
            
            # Step 3: Run audit
            if not self.run_audit(project_name):
                logger.error(f"Failed to run audit on {org}/{repo}")
                return False
            
            # Step 4: Generate report
            if not self.generate_report(project_name, report_path):
                logger.error(f"Failed to generate report for {org}/{repo}")
                return False
            
            logger.info(f"✓ Successfully processed {org}/{repo}")
            logger.info(f"  Report: {report_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error processing {org}/{repo}: {e}")
            return False
        finally:
            # Cleanup cloned repository
            try:
                if clone_dir.exists():
                    shutil.rmtree(clone_dir)
                    logger.debug(f"Cleaned up temporary directory: {clone_dir}")
            except Exception as e:
                logger.warning(f"Could not cleanup {clone_dir}: {e}")
    
    def run(self) -> Dict[str, int]:
        """
        Run the batch scanner on all filtered repositories.
        
        Returns:
            Dictionary with success/failure counts
        """
        logger.info("\n" + "="*80)
        logger.info("Starting Watchtower Batch Scanner")
        logger.info("="*80 + "\n")
        
        # Parse CSV
        repos = self.parse_csv()
        
        if not repos:
            logger.warning("No repositories to process")
            return {'success': 0, 'failed': 0, 'total': 0}
        
        # Process each repository
        results = {'success': 0, 'failed': 0, 'total': len(repos)}
        
        for idx, repo_info in enumerate(repos, 1):
            logger.info(f"\nProcessing repository {idx}/{len(repos)}")
            
            if self.process_repository(repo_info):
                results['success'] += 1
            else:
                results['failed'] += 1
        
        # Final summary
        logger.info("\n" + "="*80)
        logger.info("Watchtower Batch Scanner Complete")
        logger.info("="*80)
        logger.info(f"Total repositories: {results['total']}")
        logger.info(f"Successful: {results['success']}")
        logger.info(f"Failed: {results['failed']}")
        logger.info(f"Output directory: {self.output_dir}")
        logger.info("="*80 + "\n")
        
        return results


def main():
    """Main entry point for the Watchtower scanner."""
    parser = argparse.ArgumentParser(
        description='Watchtower - Batch Scanner for Contract Target Radar',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process NEW and UPDATED repos
  python scripts/watchtower.py radar_output.csv
  
  # Process only NEW repos with custom output directory
  python scripts/watchtower.py radar_output.csv --output-dir ./results --filter NEW
  
  # Process specific statuses
  python scripts/watchtower.py radar_output.csv --filter NEW,UPDATED,MODIFIED
        """
    )
    
    parser.add_argument(
        'csv_file',
        help='Path to the Radar CSV file'
    )
    
    parser.add_argument(
        '--output-dir',
        default='./watchtower_output',
        help='Directory to store audit results (default: ./watchtower_output)'
    )
    
    parser.add_argument(
        '--filter',
        default='NEW,UPDATED',
        help='Comma-separated list of status values to process (default: NEW,UPDATED)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Set log level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Parse filter list
    filter_list = [s.strip() for s in args.filter.split(',')]
    
    # Run scanner
    try:
        scanner = WatchtowerScanner(
            csv_path=args.csv_file,
            output_dir=args.output_dir,
            filter_status=filter_list
        )
        results = scanner.run()
        
        # Exit with appropriate code
        sys.exit(0 if results['failed'] == 0 else 1)
        
    except KeyboardInterrupt:
        logger.info("\nInterrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
