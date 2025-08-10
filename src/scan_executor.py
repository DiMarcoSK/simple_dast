import asyncio
import logging
import os
import subprocess
from typing import Optional, Tuple

import aiofiles
from rich.status import Status

from config import ScanConfig

logger = logging.getLogger(__name__)

class ScanExecutor:
    """Executes security scanning commands with proper error handling"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.results = {}
    
    async def run_command_async(self, command: str, output_file: Optional[str] = None, status: Optional[Status] = None) -> Tuple[bool, str]:
        """Execute a command asynchronously"""
        try:
            if status:
                status.update(f"Executing: {command}")
            else:
                logger.info(f"Executing: {command}")
            
            # Set up environment with proper PATH for Go tools
            env = os.environ.copy()
            go_paths = [
                os.path.expanduser("~/.go/bin"),
                os.path.expanduser("~/go/bin"),
                "/usr/local/go/bin"
            ]
            
            for path in go_paths:
                if os.path.exists(path):
                    env["PATH"] = path + os.pathsep + env.get("PATH", "")
            
            # Handle shell commands (those with pipes)
            if '|' in command:
                process = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env
                )
            else:
                process = await asyncio.create_subprocess_exec(
                    *command.split(),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env
                )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.config.timeout
            )
            
            if process.returncode == 0:
                output = stdout.decode('utf-8', errors='ignore')
                if output_file:
                    async with aiofiles.open(output_file, 'w') as f:
                        await f.write(output)
                if status:
                    status.update(f"Command completed successfully: {command}")
                else:
                    logger.info(f"Command completed successfully: {command}")
                return True, output
            else:
                error_msg = stderr.decode('utf-8', errors='ignore')
                if status:
                    status.update(f"Command failed: {command}", spinner_style="bold red")
                else:
                    logger.error(f"Command failed: {command}\nError: {error_msg}")
                return False, error_msg
                
        except asyncio.TimeoutError:
            if status:
                status.update(f"Command timed out: {command}", spinner_style="bold red")
            else:
                logger.error(f"Command timed out: {command}")
            return False, "Command timed out"
        except Exception as e:
            if status:
                status.update(f"Unexpected error executing command: {command}", spinner_style="bold red")
            else:
                logger.error(f"Unexpected error executing command: {command}\nError: {e}")
            return False, str(e)
    
    def run_command_sync(self, command: str, output_file: Optional[str] = None) -> Tuple[bool, str]:
        """Execute a command synchronously"""
        try:
            logger.info(f"Executing: {command}")
            
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=self.config.timeout
            )
            
            if result.returncode == 0:
                output = result.stdout
                if output_file:
                    with open(output_file, 'w') as f:
                        f.write(output)
                logger.info(f"Command completed successfully: {command}")
                return True, output
            else:
                logger.error(f"Command failed: {command}\nError: {result.stderr}")
                return False, result.stderr
                
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {command}")
            return False, "Command timed out"
        except Exception as e:
            logger.error(f"Unexpected error executing command: {command}\nError: {e}")
            return False, str(e)
