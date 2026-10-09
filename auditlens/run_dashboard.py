import os
import sys

# Support running from inside the auditlens directory
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)

from auditlens.ui.dashboard import start_server

if __name__ == "__main__":
    start_server(port=8085)
