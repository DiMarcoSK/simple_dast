
import argparse
import asyncio
import logging
import subprocess
import sys
from typing import Optional

import yaml

from config import ScanConfig
from scanner import VulnerabilityScanner
from tool_manager import ToolManager

def load_config(config_file: str) -> Optional[ScanConfig]:
    """Load configuration from YAML file"""
    try:
        with open(config_file, 'r') as f:
            config_data = yaml.safe_load(f)
        
        return ScanConfig(**config_data)
    except Exception as e:
        logging.error(f"Failed to load config file: {e}")
        return None

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Advanced DAST Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s -t 20 example.com
  %(prog)s --config config.yaml example.com
        """
    )
    
    parser.add_argument('target', type=str, help='Target domain to scan')
    parser.add_argument('-t', '--threads', type=int, default=10, 
                       help='Number of threads to use (default: 10)')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Command timeout in seconds (default: 30)')
    parser.add_argument('--output-dir', type=str, default='Targets',
                       help='Output directory (default: Targets)')
    parser.add_argument('--nuclei-templates', type=str, default='~/nuclei-templates/',
                       help='Path to Nuclei templates (default: ~/nuclei-templates/)')
    parser.add_argument('--config', type=str, help='Configuration file (YAML)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load configuration
    config = None
    if args.config:
        config = load_config(args.config)
    
    if not config:
        config = ScanConfig(
            target=args.target,
            threads=args.threads,
            timeout=args.timeout,
            output_dir=args.output_dir,
            nuclei_templates=args.nuclei_templates
        )
    
    # Validate target
    if not config.target or '.' not in config.target:
        logging.error("❌ Invalid target domain")
        sys.exit(1)
    
    # Check if Go is available
    try:
        go_result = subprocess.run(["go", "version"], capture_output=True, text=True, timeout=10)
        if go_result.returncode != 0:
            logging.error("❌ Go is not installed or not accessible")
            logging.error("💡 Install Go from: https://golang.org/dl/")
            sys.exit(1)
        logging.info(f"✅ Go found: {go_result.stdout.strip()}")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        logging.error("❌ Go is not installed or not accessible")
        logging.error("💡 Install Go from: https://golang.org/dl/")
        sys.exit(1)
    
    # Check and install tools
    logging.info("🚀 Starting DAST Vulnerability Scanner...")
    logging.info(f"🎯 Target: {config.target}")
    logging.info(f"🧵 Threads: {config.threads}")
    logging.info(f"⏱️  Timeout: {config.timeout}s")
    logging.info(f"📁 Output: {config.output_dir}")
    
    if not ToolManager.check_and_install_tools():
        logging.error("❌ Failed to install required tools")
        logging.error("💡 Troubleshooting tips:")
        logging.error("   1. Ensure Go is installed: go version")
        logging.error("   2. Check your internet connection")
        logging.error("   3. Verify you have write permissions to ~/.go")
        logging.error("   4. Try running: export GOPATH=~/.go && export PATH=$PATH:$GOPATH/bin")
        sys.exit(1)
    
    # Run scan
    scanner = VulnerabilityScanner(config)
    
    try:
        success = asyncio.run(scanner.run_scan())
        if success:
            logging.info("🎉 Scan completed successfully!")
            logging.info(f"📁 Results saved in: {config.output_dir}")
            logging.info("📊 Check the generated reports for detailed findings")
            sys.exit(0)
        else:
            logging.error("❌ Scan failed")
            logging.error("💡 Check the log file 'dast_scan.log' for details")
            sys.exit(1)
    except KeyboardInterrupt:
        logging.info("⏹️  Scan interrupted by user")
        logging.info("💡 Partial results may be available in the output directory")
        sys.exit(130)
    except Exception as e:
        logging.error(f"❌ Unexpected error: {e}")
        logging.error("💡 Check the log file 'dast_scan.log' for details")
        sys.exit(1)

if __name__ == '__main__':
    main()
