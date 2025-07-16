import json
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

def generate_json_report(target, scan_results, brute_results, fuzz_results, cve_results, exploit_results=None):
    report = {
        "target": target,
        "scan_results": scan_results,
        "brute_results": brute_results,
        "fuzz_results": fuzz_results,
        "exploit_results": exploit_results or {},
        "cve_results": cve_results,
        "timestamp": datetime.now().isoformat()
    }
    reports_dir = os.path.join(os.path.dirname(__file__), '..', 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    json_path = os.path.join(reports_dir, f"report_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(json_path, 'w') as f:
        json.dump(report, f, indent=4)
    print(f"[+] JSON report saved to {json_path}")
    return json_path

def generate_html_report(json_report_path):
    env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))
    template = env.get_template('report_template.html')

    with open(json_report_path, 'r') as f:
        data = json.load(f)

    html_content = template.render(report=data)

    html_path = json_report_path.replace('.json', '.html')
    with open(html_path, 'w') as f:
        f.write(html_content)
    print(f"[+] HTML report saved to {html_path}")
    return html_path