import os
import sys
import json
import urllib.parse
from http.server import HTTPServer, SimpleHTTPRequestHandler

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from auditlens.adapters.package_adapter import SharePackageAdapter
from auditlens.engine.audit_engine import AuditEngine

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
SHARE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "share")

class AuditLensRequestHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/api/audit-report":
            query_params = urllib.parse.parse_qs(parsed_url.query)
            dataset = query_params.get("dataset", ["dataset_a"])[0]
            report_data = self._generate_report(dataset)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(report_data).encode("utf-8"))
            return

        if path == "/" or path == "/index.html":
            file_path = os.path.join(STATIC_DIR, "index.html")
            self._serve_file(file_path, "text/html")
            return
        elif path == "/style.css":
            file_path = os.path.join(STATIC_DIR, "style.css")
            self._serve_file(file_path, "text/css")
            return
        elif path == "/app.js":
            file_path = os.path.join(STATIC_DIR, "app.js")
            self._serve_file(file_path, "text/javascript")
            return

        super().do_GET()

    def _serve_file(self, filepath: str, content_type: str):
        if os.path.exists(filepath):
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.end_headers()
            with open(filepath, "rb") as f:
                self.wfile.write(f.read())
        else:
            self.send_error(404, "File Not Found")

    def _generate_report(self, dataset: str) -> dict:
        engine = AuditEngine(pass_threshold=85.0)

        if dataset.startswith("rag_"):
            package_dir = os.path.join(SHARE_DIR, "rag_datasets")
        else:
            package_dir = os.path.join(SHARE_DIR, "resume_datasets")

        adapter = SharePackageAdapter(package_dir)
        report = engine.run_audit(adapter, dataset=dataset)
        return report.model_dump()

def start_server(port: int = 8085):
    server_address = ('', port)
    httpd = HTTPServer(server_address, AuditLensRequestHandler)
    print(f"AuditLens Dashboard Server running at http://localhost:{port}/")
    httpd.serve_forever()

if __name__ == "__main__":
    start_server()
