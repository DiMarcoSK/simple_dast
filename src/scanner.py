
import json
import logging
import os
from datetime import datetime
from pathlib import Path

import aiofiles
import aiohttp
from rich.status import Status

from config import ScanConfig
from extended_scanner import ExtendedScanner
from scan_executor import ScanExecutor

logger = logging.getLogger(__name__)

class VulnerabilityScanner:
    """Main vulnerability scanning orchestrator"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.executor = ScanExecutor(config)
        self.extended_scanner = ExtendedScanner(config, self.executor)
        self.setup_directories()
    
    def setup_directories(self):
        """Create necessary output directories"""
        dirs = [
            self.config.output_dir,
            os.path.join(self.config.output_dir, "Subdomains"),
            os.path.join(self.config.output_dir, "Vulns"),
            os.path.join(self.config.output_dir, "WebAppContent"),
            os.path.join(self.config.output_dir, "Reports")
        ]
        
        for dir_path in dirs:
            Path(dir_path).mkdir(parents=True, exist_ok=True)
            logger.info(f"Created directory: {dir_path}")
    
    async def download_wordlist(self) -> str:
        """Download the common wordlist for fuzzing"""
        wordlist_path = "/tmp/common.txt"
        
        if not os.path.exists(wordlist_path):
            with Status("Downloading common wordlist...", spinner="dots") as status:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(self.config.wordlist_url) as response:
                            if response.status == 200:
                                content = await response.text()
                                async with aiofiles.open(wordlist_path, 'w') as f:
                                    await f.write(content)
                                status.update("Wordlist downloaded successfully", spinner_style="bold green")
                            else:
                                status.update(f"Failed to download wordlist: HTTP {response.status}", spinner_style="bold red")
                                return ""
                except Exception as e:
                    status.update(f"Error downloading wordlist: {e}", spinner_style="bold red")
                    return ""
        else:
            logger.info("Wordlist already exists")
        
        return wordlist_path
    
    async def discover_subdomains(self) -> str:
        """Discover subdomains using multiple tools"""
        with Status("Discovering subdomains...", spinner="earth") as status:
            subs_file = os.path.join(self.config.output_dir, "Subdomains", f"{self.config.target}.subs")
            
            # Create empty file first
            with open(subs_file, 'w') as f:
                pass
            
            # Run subdomain discovery tools sequentially to avoid conflicts
            status.update("Running subfinder...")
            success1, output1 = await self.executor.run_command_async(
                f"subfinder -d {self.config.target} -silent", 
                None,
                status=status
            )
            
            if success1 and output1:
                with open(subs_file, 'a') as f:
                    f.write(output1)
            
            status.update("Running amass...")
            # Use longer timeout for amass as it can take time
            original_timeout = self.config.timeout
            self.config.timeout = max(120, original_timeout)  # At least 2 minutes for amass
            
            success2, output2 = await self.executor.run_command_async(
                f"amass enum -d {self.config.target} -silent", 
                None,
                status=status
            )
            
            # Restore original timeout
            self.config.timeout = original_timeout
            
            if success2 and output2:
                with open(subs_file, 'a') as f:
                    f.write(output2)
            
            status.update("Running assetfinder...")
            success3, output3 = await self.executor.run_command_async(
                f"assetfinder --subs-only {self.config.target}",
                None,
                status=status
            )

            if success3 and output3:
                with open(subs_file, 'a') as f:
                    f.write(output3)

            # Count discovered subdomains
            if os.path.exists(subs_file):
                with open(subs_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
                # Remove duplicates
                unique_subdomains = list(set(subdomains))
                with open(subs_file, 'w') as f:
                    for subdomain in unique_subdomains:
                        f.write(f"{subdomain}\n")
                status.update(f"Discovered {len(unique_subdomains)} unique subdomains", spinner_style="bold green")
            else:
                status.update("No subdomains file created", spinner_style="bold red")
                unique_subdomains = []
            
            return subs_file
    
    async def probe_http_services(self, subs_file: str) -> str:
        """Probe discovered subdomains for HTTP/HTTPS services"""
        with Status("Probing HTTP/HTTPS services...", spinner="moon") as status:
            httpprobe_file = os.path.join(self.config.output_dir, "Subdomains", f"{self.config.target}.httpprobe")
            
            # Read subdomains from file
            try:
                with open(subs_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
                
                if not subdomains:
                    status.update("No subdomains to probe", spinner_style="bold yellow")
                    return httpprobe_file
                
                status.update(f"Probing {len(subdomains)} subdomains...")
                
                # Create a temporary file with subdomains for httprobe
                temp_subs_file = f"{subs_file}.temp"
                with open(temp_subs_file, 'w') as f:
                    for subdomain in subdomains:
                        f.write(f"{subdomain}\n")
                
                # Run httprobe (it reads from stdin, so we need to pipe the file content)
                success, output = await self.executor.run_command_async(
                    f"cat {temp_subs_file} | httprobe -c {self.config.threads}",
                    httpprobe_file,
                    status=status
                )
                
                # Clean up temp file
                if os.path.exists(temp_subs_file):
                    os.remove(temp_subs_file)
                
                if success and os.path.exists(httpprobe_file):
                    with open(httpprobe_file, 'r') as f:
                        live_hosts = [line.strip() for line in f if line.strip()]
                    status.update(f"Found {len(live_hosts)} live HTTP/HTTPS services", spinner_style="bold green")
                else:
                    status.update("HTTP probing failed or no results", spinner_style="bold red")
                    live_hosts = []
                    
            except Exception as e:
                status.update(f"Error during HTTP probing: {e}", spinner_style="bold red")
                live_hosts = []
            
            return httpprobe_file
    
    async def discover_web_content(self, httpprobe_file: str, wordlist_path: str):
        """Discover web content using multiple tools"""
        with Status("Discovering web content...", spinner="earth") as status:
            webapp_dir = os.path.join(self.config.output_dir, "WebAppContent")
            
            # Check if httprobe file exists and has content
            if not os.path.exists(httpprobe_file):
                status.update("HTTP probe file not found, skipping web content discovery", spinner_style="bold yellow")
                return
            
            with open(httpprobe_file, 'r') as f:
                live_hosts = [line.strip() for line in f if line.strip()]
            
            if not live_hosts:
                status.update("No live hosts found, skipping web content discovery", spinner_style="bold yellow")
                return
            
            status.update(f"Starting content discovery for {len(live_hosts)} live hosts...")
            
            # Run content discovery tools sequentially to avoid conflicts
            all_urls = set()
            
            # Katana crawling
            try:
                katana_output = os.path.join(webapp_dir, f"{self.config.target}.katana")
                status.update("Running Katana crawler...")
                success, output = await self.executor.run_command_async(
                    f"katana -no-color -system-chrome -list {httpprobe_file} -output {katana_output}",
                    katana_output,
                    status=status
                )
                if success and os.path.exists(katana_output):
                    with open(katana_output, 'r') as f:
                        urls = [line.strip() for line in f if line.strip()]
                        all_urls.update(urls)
                    status.update(f"Katana discovered {len(urls)} URLs", spinner_style="bold green")
            except Exception as e:
                status.update(f"Katana failed: {e}", spinner_style="bold red")
            
            # FFuf fuzzing
            try:
                ffuf_output = os.path.join(webapp_dir, f"{self.config.target}.ffuf")
                status.update("Running FFuf fuzzer...")
                success, output = await self.executor.run_command_async(
                    f"ffuf -u HOST/WORD -w {httpprobe_file}:HOST -w {wordlist_path}:WORD -ac -o {ffuf_output}",
                    ffuf_output,
                    status=status
                )
                if success and os.path.exists(ffuf_output):
                    # Parse FFuf JSON output
                    try:
                        with open(ffuf_output, 'r') as f:
                            content = f.read()
                            if content.strip():
                                # Simple extraction of URLs from FFuf output
                                lines = content.split('\n')
                                for line in lines:
                                    if line.strip() and 'HOST' in line and 'WORD' in line:
                                        # This is a basic extraction, FFuf output can be complex
                                        pass
                    except Exception as e:
                        status.update(f"Error parsing FFuf output: {e}", spinner_style="bold red")
                    status.update("FFuf fuzzing completed", spinner_style="bold green")
            except Exception as e:
                status.update(f"FFuf failed: {e}", spinner_style="bold red")
            
            # GAU URL discovery
            try:
                gau_output = os.path.join(webapp_dir, f"{self.config.target}.gau")
                status.update("Running GAU URL discovery...")
                
                # Process hosts one by one to avoid command line length issues
                for host in live_hosts[:10]:  # Limit to first 10 hosts to avoid timeouts
                    try:
                        success, output = await self.executor.run_command_async(
                            f"gau --subs --threads {self.config.threads} {host}",
                            None,
                            status=status
                        )
                        if success and output:
                            with open(gau_output, 'a') as f:
                                f.write(output)
                    except Exception as e:
                        status.update(f"GAU failed for {host}: {e}", spinner_style="bold red")
                        continue
                
                if os.path.exists(gau_output):
                    with open(gau_output, 'r') as f:
                        urls = [line.strip() for line in f if line.strip()]
                        all_urls.update(urls)
                    status.update(f"GAU discovered {len(urls)} URLs", spinner_style="bold green")
            except Exception as e:
                status.update(f"GAU failed: {e}", spinner_style="bold red")
            
            # Gospider crawling
            try:
                gospider_output = os.path.join(webapp_dir, f"{self.config.target}.gospider")
                status.update("Running Gospider crawler...")
                
                for host in live_hosts[:10]:
                    try:
                        success, output = await self.executor.run_command_async(
                            f"gospider -s {host} -c 10 -d 1 --other-source",
                            None,
                            status=status
                        )
                        if success and output:
                            with open(gospider_output, 'a') as f:
                                f.write(output)
                    except Exception as e:
                        status.update(f"Gospider failed for {host}: {e}", spinner_style="bold red")
                        continue
                
                if os.path.exists(gospider_output):
                    with open(gospider_output, 'r') as f:
                        urls = [line.strip() for line in f if line.strip()]
                        all_urls.update(urls)
                    status.update(f"Gospider discovered {len(urls)} URLs", spinner_style="bold green")
            except Exception as e:
                status.update(f"Gospider failed: {e}", spinner_style="bold red")

            # Write combined URLs
            if all_urls:
                urls_file = os.path.join(webapp_dir, f"{self.config.target}.urls")
                with open(urls_file, 'w') as f:
                    for url in sorted(all_urls):
                        f.write(f"{url}\n")
                status.update(f"Combined discovery found {len(all_urls)} unique URLs", spinner_style="bold green")
            else:
                status.update("No URLs discovered from any tool", spinner_style="bold yellow")

    async def run_extended_scan(self, live_hosts_file: str):
        """Run the extended scanning workflow."""
        await self.extended_scanner.run_extended_scan(live_hosts_file)

    async def run_vulnerability_scan(self, httpprobe_file: str):
        """Run Nuclei vulnerability scan"""
        with Status("Running vulnerability scan with Nuclei...", spinner="dots") as status:
            vulns_dir = os.path.join(self.config.output_dir, "Vulns")
            nuclei_output = os.path.join(vulns_dir, f"{self.config.target}.nuclei.json")
            
            # Build Nuclei command with proper templates path
            severity_flags = f"-severity {','.join(self.config.nuclei_severity)}"
            
            # Check if custom templates path exists, otherwise use default
            templates_path = os.path.expanduser(self.config.nuclei_templates)
            if not os.path.exists(templates_path):
                # Try to use default nuclei templates location
                default_templates = os.path.expanduser("~/.local/nuclei-templates")
                if os.path.exists(default_templates):
                    templates_path = default_templates
                    status.update(f"Using default nuclei templates: {templates_path}")
                else:
                    status.update("Nuclei templates not found, using built-in templates", spinner_style="bold yellow")
                    templates_path = ""
            
            nuclei_cmd = f"nuclei -list {httpprobe_file} -s {severity_flags} -json-export {nuclei_output}"
            if templates_path:
                nuclei_cmd += f" -t {templates_path}"
            
            success, output = await self.executor.run_command_async(nuclei_cmd, nuclei_output, status=status)
            
            if success:
                status.update("Vulnerability scan completed successfully", spinner_style="bold green")
            else:
                status.update("Vulnerability scan failed", spinner_style="bold red")
    
    def generate_report(self):
        """Generate a comprehensive scan report"""
        logger.info("Generating scan report...")
        
        report_file = os.path.join(self.config.output_dir, "Reports", f"{self.config.target}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        report = {
            "scan_info": {
                "target": self.config.target,
                "timestamp": datetime.now().isoformat(),
                "threads": self.config.threads,
                "timeout": self.config.timeout
            },
            "results": {
                "subdomains": [],
                "live_hosts": [],
                "urls": [],
                "extended_urls": [],
                "vulnerabilities": []
            }
        }
        
        # Collect subdomain results
        subs_file = os.path.join(self.config.output_dir, "Subdomains", f"{self.config.target}.subs")
        if os.path.exists(subs_file):
            with open(subs_file, 'r') as f:
                report["results"]["subdomains"] = [line.strip() for line in f if line.strip()]
        
        # Collect live host results
        httpprobe_file = os.path.join(self.config.output_dir, "Subdomains", f"{self.config.target}.httpprobe")
        if os.path.exists(httpprobe_file):
            with open(httpprobe_file, 'r') as f:
                report["results"]["live_hosts"] = [line.strip() for line in f if line.strip()]
        
        # Collect web content results
        webapp_dir = os.path.join(self.config.output_dir, "WebAppContent")
        urls_file = os.path.join(webapp_dir, f"{self.config.target}.urls")
        if os.path.exists(urls_file):
            with open(urls_file, 'r') as f:
                report["results"]["urls"] = [line.strip() for line in f if line.strip()]
        
        extended_urls_file = os.path.join(webapp_dir, f"{self.config.target}.extended_urls")
        if os.path.exists(extended_urls_file):
            with open(extended_urls_file, 'r') as f:
                report["results"]["extended_urls"] = [line.strip() for line in f if line.strip()]

        # Collect vulnerability results
        vulns_dir = os.path.join(self.config.output_dir, "Vulns")
        nuclei_output = os.path.join(vulns_dir, f"{self.config.target}.nuclei.json")
        if os.path.exists(nuclei_output):
            with open(nuclei_output, 'r') as f:
                for line in f:
                    try:
                        report["results"]["vulnerabilities"].append(json.loads(line))
                    except json.JSONDecodeError:
                        # Handle cases where a line is not a valid JSON object
                        logger.warning(f"Could not parse line in nuclei output: {line.strip()}")
        
        # Write report
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Scan report generated: {report_file}")
        return report_file
    
    async def run_scan(self) -> bool:
        """Execute the complete vulnerability scan"""
        try:
            logger.info(f"Starting DAST scan for target: {self.config.target}")
            start_time = datetime.now()
            
            scan_phases = {
                "wordlist_download": False,
                "subdomain_discovery": False,
                "http_probing": False,
                "web_content_discovery": False,
                "extended_scan": False,
                "vulnerability_scanning": False
            }
            
            # Download wordlist
            wordlist_path = await self.download_wordlist()
            if wordlist_path:
                scan_phases["wordlist_download"] = True
            else:
                wordlist_path = "/usr/share/wordlists/dirb/common.txt"  # Fallback
            
            # Discover subdomains
            subs_file = await self.discover_subdomains()
            if os.path.exists(subs_file):
                scan_phases["subdomain_discovery"] = True
            else:
                # Create empty file to continue
                subs_file = os.path.join(self.config.output_dir, "Subdomains", f"{self.config.target}.subs")
                with open(subs_file, 'w') as f:
                    f.write(f"{self.config.target}\n")  # At least scan the main domain
            
            # Probe HTTP services
            httpprobe_file = await self.probe_http_services(subs_file)
            if os.path.exists(httpprobe_file):
                scan_phases["http_probing"] = True
            else:
                # Create file with just the main domain
                httpprobe_file = os.path.join(self.config.output_dir, "Subdomains", f"{self.config.target}.httpprobe")
                with open(httpprobe_file, 'w') as f:
                    f.write(f"http://{self.config.target}\n")
                    f.write(f"https://{self.config.target}\n")
            
            # Discover web content
            try:
                await self.discover_web_content(httpprobe_file, wordlist_path)
                scan_phases["web_content_discovery"] = True
            except Exception as e:
                logger.warning(f"Web content discovery failed: {e}")
            
            # Run extended scan
            try:
                await self.run_extended_scan(httpprobe_file)
                scan_phases["extended_scan"] = True
            except Exception as e:
                logger.warning(f"Extended scan failed: {e}")

            # Run vulnerability scan
            try:
                await self.run_vulnerability_scan(httpprobe_file)
                scan_phases["vulnerability_scanning"] = True
            except Exception as e:
                logger.warning(f"Vulnerability scanning failed: {e}")
            
            # Generate report
            report_file = self.generate_report()
            
            end_time = datetime.now()
            duration = end_time - start_time
            
            # Report scan summary
            logger.info(f"\n[bold green]🎯 Scan Summary:[/bold green]")
            logger.info(f"   [bold]⏱️  Duration:[/bold] {duration}")
            logger.info(f"   [bold]📁 Results:[/bold] {self.config.output_dir}")
            logger.info(f"   [bold]📊 Report:[/bold] {report_file}")
            
            successful_phases = sum(scan_phases.values())
            total_phases = len(scan_phases)
            
            if successful_phases == total_phases:
                logger.info("[bold green]🎉 All scan phases completed successfully![/bold green]")
                return True
            elif successful_phases > 0:
                logger.info(f"[bold yellow]⚠️  {successful_phases}/{total_phases} scan phases completed[/bold yellow]")
                logger.info("[bold blue]💡 Some phases failed, but partial results are available[/bold blue]")
                return True
            else:
                logger.error("[bold red]❌ All scan phases failed[/bold red]")
                return False
            
        except Exception as e:
            logger.error(f"Scan failed with unexpected error: {e}")
            return False
