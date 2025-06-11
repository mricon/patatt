import sys
from pathlib import Path

# Add the src directory to the Python path
project_root = Path(__file__).parent
src_path = str(project_root / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

