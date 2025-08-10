
#!/usr/bin/env python3

import logging
import sys
from pathlib import Path

from rich.logging import RichHandler

# Add src directory to Python path
sys.path.append(str(Path(__file__).parent.joinpath("src")))

from main import main

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s',
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, markup=True)]
    )
    main()
