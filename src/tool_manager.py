import logging
import os
import subprocess
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class ToolInfo:
    """Information about required security tools"""
    name: str
    install_command: str
    check_command: str
    description: str

class ToolManager:
    """Manages installation and verification of required security tools"""
    
    REQUIRED_TOOLS = {
        "subfinder": ToolInfo(
            "subfinder",
            "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "subfinder -version",
            "Subdomain discovery tool"
        ),
        "amass": ToolInfo(
            "amass",
            "go install github.com/owasp/amass/v4/cmd/amass@latest",
            "amass -version",
            "Subdomain enumeration tool"
        ),
        "httprobe": ToolInfo(
            "httprobe",
            "go install github.com/tomnomnom/httprobe@latest",
            "httprobe -h",
            "HTTP/HTTPS probing tool"
        ),
        "nuclei": ToolInfo(
            "nuclei",
            "go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
            "nuclei -version",
            "Vulnerability scanner"
        ),
        "katana": ToolInfo(
            "katana",
            "go install github.com/projectdiscovery/katana/cmd/katana@latest",
            "katana -h",
            "Web crawler"
        ),
        "ffuf": ToolInfo(
            "ffuf",
            "go install github.com/ffuf/ffuf@latest",
            "ffuf -h",
            "Web fuzzer"
        ),
        "gau": ToolInfo(
            "gau",
            "go install github.com/lc/gau/v2/cmd/gau@latest",
            "gau -h",
            "URL discovery tool"
        ),
        "assetfinder": ToolInfo(
            "assetfinder",
            "go install github.com/tomnomnom/assetfinder@latest",
            "assetfinder --help",
            "Subdomain discovery tool from tomnomnom"
        ),
        "gospider": ToolInfo(
            "gospider",
            "go install github.com/jaeles-project/gospider@latest",
            "gospider -h",
            "Fast web spider"
        )
    }
    
    @staticmethod
    def check_tool_installed(tool_name: str) -> bool:
        """Check if a tool is installed and accessible"""
        try:
            # First try using 'which' command
            result = subprocess.run(
                ["which", tool_name], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            if result.returncode == 0:
                return True
            
            # If 'which' fails, try to find in common Go binary paths
            go_paths = [
                os.path.expanduser("~/.go/bin"),
                os.path.expanduser("~/go/bin"),
                "/usr/local/go/bin",
                "/usr/local/bin",
                "/usr/bin"
            ]
            
            for path in go_paths:
                if os.path.exists(os.path.join(path, tool_name)):
                    return True
            
            return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    @staticmethod
    def verify_tool_functionality(tool_info: ToolInfo) -> bool:
        """Verify that a tool works correctly"""
        try:
            # Set up PATH to include Go binary directories
            env = os.environ.copy()
            go_paths = [
                os.path.expanduser("~/.go/bin"),
                os.path.expanduser("~/go/bin"),
                "/usr/local/go/bin"
            ]
            
            for path in go_paths:
                if os.path.exists(path):
                    env["PATH"] = path + os.pathsep + env.get("PATH", "")
            
            result = subprocess.run(
                tool_info.check_command.split(),
                capture_output=True,
                text=True,
                timeout=15,
                env=env
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return False
    
    @classmethod
    def install_tool(cls, tool_info: ToolInfo) -> bool:
        """Install a required tool"""
        logger.info(f"Installing {tool_info.name}...")
        
        # Set up Go environment
        env = os.environ.copy()
        go_path = os.path.expanduser("~/.go")
        env["GOPATH"] = go_path
        env["PATH"] = os.path.join(go_path, "bin") + os.pathsep + env.get("PATH", "")
        
        # Also check for Go installation in other common locations
        go_bin_paths = [
            os.path.expanduser("~/go/bin"),
            "/usr/local/go/bin"
        ]
        
        for path in go_bin_paths:
            if os.path.exists(path):
                env["PATH"] = path + os.pathsep + env["PATH"]
        
        try:
            result = subprocess.run(
                tool_info.install_command.split(),
                check=True,
                timeout=300,
                capture_output=True,
                text=True,
                env=env
            )
            logger.info(f"Successfully installed {tool_info.name}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install {tool_info.name}: {e}")
            if e.stderr:
                logger.error(f"Installation error details: {e.stderr}")
            return False
        except subprocess.TimeoutExpired:
            logger.error(f"Installation of {tool_info.name} timed out")
            return False
    
    @classmethod
    def check_and_install_tools(cls) -> bool:
        """Check and install all required tools"""
        missing_tools = []
        broken_tools = []
        available_tools = []
        
        logger.info("🔍 Checking required security tools...")
        
        for tool_name, tool_info in cls.REQUIRED_TOOLS.items():
            if not cls.check_tool_installed(tool_name):
                missing_tools.append((tool_name, tool_info))
                logger.warning(f"❌ {tool_name} is not installed")
            elif not cls.verify_tool_functionality(tool_info):
                broken_tools.append((tool_name, tool_info))
                logger.warning(f"⚠️  {tool_name} is installed but not working properly")
            else:
                available_tools.append(tool_name)
                logger.info(f"✅ {tool_name} is available and working")
        
        # Report tool status
        logger.info(f"\n📊 Tool Status Summary:")
        logger.info(f"   ✅ Available: {len(available_tools)} tools")
        logger.info(f"   ❌ Missing: {len(missing_tools)} tools")
        logger.info(f"   ⚠️  Broken: {len(broken_tools)} tools")
        
        if available_tools:
            logger.info(f"   Available tools: {', '.join(available_tools)}")
        
        if missing_tools:
            logger.info(f"\n🔧 Installing missing tools...")
            for tool_name, tool_info in missing_tools:
                logger.info(f"   Installing {tool_name}...")
                if not cls.install_tool(tool_info):
                    logger.error(f"   ❌ Failed to install {tool_name}")
                    return False
                else:
                    logger.info(f"   ✅ Successfully installed {tool_name}")
        
        if broken_tools:
            logger.info(f"\n🔧 Reinstalling broken tools...")
            for tool_name, tool_info in broken_tools:
                logger.info(f"   Reinstalling {tool_name}...")
                if not cls.install_tool(tool_info):
                    logger.error(f"   ❌ Failed to reinstall {tool_name}")
                    return False
                else:
                    logger.info(f"   ✅ Successfully reinstalled {tool_name}")
        
        if not missing_tools and not broken_tools:
            logger.info("🎉 All required tools are available and working!")
        else:
            logger.info("🎉 Tool installation completed!")
        
        return True