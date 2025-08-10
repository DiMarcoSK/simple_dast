
import logging
from dataclasses import dataclass, field
from typing import List

logger = logging.getLogger(__name__)

@dataclass
class ScanConfig:
    """Configuration for the vulnerability scan"""
    target: str
    threads: int = 10
    timeout: int = 1200
    output_dir: str = "Targets"
    nuclei_templates: str = "~/nuclei-templates/"
    wordlist_url: str = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
    nuclei_severity: List[str] = field(default_factory=lambda: ["info", "low", "medium", "high", "critical"])
