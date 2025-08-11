
import logging
import os
from pathlib import Path

from rich.status import Status

from config import ScanConfig
from scan_executor import ScanExecutor

logger = logging.getLogger(__name__)

class ExtendedScanner:
    """A scanner for running additional, chained discovery tools."""

    def __init__(self, config: ScanConfig, executor: ScanExecutor):
        self.config = config
        self.executor = executor
        self.webapp_dir = os.path.join(self.config.output_dir, "WebAppContent")
        Path(self.webapp_dir).mkdir(parents=True, exist_ok=True)

    async def run_hakrawler(self, live_hosts_file: str) -> str:
        """Run hakrawler to discover URLs."""
        hakrawler_output = os.path.join(self.webapp_dir, f"{self.config.target}.hakrawler")
        with Status("Running hakrawler...", spinner="bouncingBar") as status:
            command = f"cat {live_hosts_file} | hakrawler -d 2 -u"
            success, output = await self.executor.run_command_async(command, hakrawler_output, status=status)
            if not success:
                logger.error("Hakrawler scan failed.")
                return ""
            return hakrawler_output

    async def run_waybackurls(self, live_hosts_file: str) -> str:
        """Run waybackurls to fetch historical URLs."""
        wayback_output = os.path.join(self.webapp_dir, f"{self.config.target}.wayback")
        with Status("Running waybackurls...", spinner="bouncingBar") as status:
            command = f"cat {live_hosts_file} | waybackurls"
            success, output = await self.executor.run_command_async(command, wayback_output, status=status)
            if not success:
                logger.error("Waybackurls scan failed.")
                return ""
            return wayback_output

    async def run_dirsearch(self, live_hosts_file: str) -> str:
        """Run dirsearch to find hidden directories and files."""
        dirsearch_output = os.path.join(self.webapp_dir, f"{self.config.target}.dirsearch")
        with Status("Running dirsearch...", spinner="bouncingBar") as status:
            command = f"python3 /tmp/dirsearch/dirsearch.py -l {live_hosts_file} -o {dirsearch_output}"
            success, output = await self.executor.run_command_async(command, dirsearch_output, status=status)
            if not success:
                logger.error("Dirsearch scan failed.")
                return ""
            return dirsearch_output

    async def run_extended_scan(self, live_hosts_file: str):
        """Run the extended scanning workflow."""
        hakrawler_output = await self.run_hakrawler(live_hosts_file)
        wayback_output = await self.run_waybackurls(live_hosts_file)
        dirsearch_output = await self.run_dirsearch(live_hosts_file)

        # Merge and deduplicate results
        all_urls = set()
        for file in [hakrawler_output, wayback_output]:
            if file and os.path.exists(file):
                with open(file, 'r') as f:
                    all_urls.update(line.strip() for line in f)
        
        if dirsearch_output and os.path.exists(dirsearch_output):
             with open(dirsearch_output, 'r') as f:
                all_urls.update(line.strip() for line in f)

        combined_urls_file = os.path.join(self.webapp_dir, f"{self.config.target}.extended_urls")
        with open(combined_urls_file, 'w') as f:
            for url in sorted(all_urls):
                f.write(f"{url}\n")
        
        logger.info(f"Extended scan complete. Found {len(all_urls)} unique URLs.")
