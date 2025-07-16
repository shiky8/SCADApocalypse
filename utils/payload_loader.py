import os

def load_payloads(filename):
    path = os.path.join(os.path.dirname(__file__), '..', 'payloads', filename)
    try:
        with open(path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[-] Failed to load payloads from {filename}: {e}")
        return []
