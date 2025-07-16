import csv
import requests
from utils.logger import setup_logger

logger = setup_logger()

SCADAPASS_CSV_URL = "https://raw.githubusercontent.com/scadastrangelove/SCADAPASS/master/scadapass.csv"

def update_scadapass_local(filename='scadapass_local.csv'):
    try:
        response = requests.get(SCADAPASS_CSV_URL, timeout=10)
        response.raise_for_status()
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(response.text)
        logger.info(f"SCADAPASS updated and saved to {filename}")
        return filename
    except Exception as e:
        logger.error(f"Failed to update SCADAPASS: {e}")
        return None

def parse_user_pass(cred):
    pairs = []
    cred = cred.strip()
    if not cred:
        return pairs
    for entry in cred.split(','):
        entry = entry.strip()
        if ':' in entry:
            user, pw = entry.split(':', 1)
            pairs.append((user.strip(), pw.strip()))
        else:
            # If only password, username is empty or generic
            pairs.append(('', entry.strip()))
    return pairs

# def load_scadapass_credentials(filename='scadapass_local.csv'):
#     creds = {}
#     try:
#         with open(filename, 'r', encoding='utf-8') as f:
#             reader = csv.reader(f, delimiter='\t')
#             for row in reader:
#                 if not row or row[0].startswith('#') or len(row) < 3:
#                     continue  # skip comments or bad rows
#                 vendor = row[0].strip()
#                 device = row[1].strip()
#                 raw_creds = row[2].strip()

#                 system = f"{vendor} {device}"
#                 for user, password in parse_user_pass(raw_creds):
#                     if system not in creds:
#                         creds[system] = []
#                     creds[system].append((user, password))

#         logger.info(f"Loaded SCADAPASS credentials from {filename}")
#     except Exception as e:
#         logger.error(f"Failed to load SCADAPASS credentials: {e}")
#     return creds
def load_scadapass_credentials(filename='scadapass_local.csv'):
    creds = {}
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            reader = csv.reader(f, delimiter=',')
            for row in reader:
                if not row or row[0].startswith('#') or len(row) < 3:
                    continue  # skip comments or malformed rows
                vendor = row[0].strip()
                device = row[1].strip()
                raw_creds = row[2].strip()

                system = f"{vendor} {device}"
                for user, password in parse_user_pass(raw_creds):
                    if system not in creds:
                        creds[system] = []
                    creds[system].append((user, password))

        logger.info(f"Loaded SCADAPASS credentials from {filename}")
    except Exception as e:
        logger.error(f"Failed to load SCADAPASS credentials: {e}")
    return creds
