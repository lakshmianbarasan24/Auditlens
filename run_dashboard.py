import os
import sys

# Ensure root directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auditlens.ui.dashboard import start_server

if __name__ == "__main__":
    start_server(port=8085)
