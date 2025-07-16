import requests
from utils.logger import setup_logger

logger = setup_logger()

CIRCL_API = "https://cve.circl.lu/api/search/"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="

def cve_search(service_banner):
    query = service_banner.strip().lower().replace("/", "").replace(" ", "%20")
    results_list = []

    logger.info(f"[+] Starting CVE search for: {service_banner}")

    # CIRCL
    try:
        logger.debug(f"[CIRCL] Searching: {query}")
        response = requests.get(CIRCL_API + query, timeout=5)
        if response.status_code == 200:
            circl_data = response.json()
            for cve in circl_data.get('results', []):
                results_list.append({
                    "id": cve.get("id"),
                    "description": cve.get("summary", "No description available.")
                })
        else:
            logger.warning(f"[CIRCL] API error: {response.status_code}")
    except Exception as e:
        logger.error(f"[CIRCL] Exception: {e}")

    # NVD fallback if no CIRCL CVEs found
    if not results_list:
        try:
            logger.debug(f"[NVD] Searching: {query}")
            response = requests.get(NVD_API + query, timeout=8)
            if response.status_code == 200:
                nvd_data = response.json()
                for entry in nvd_data.get("vulnerabilities", []):
                    cve = entry.get("cve", {})
                    cve_id = cve.get("id")
                    descriptions = cve.get("descriptions", [])
                    en_desc = next((d['value'] for d in descriptions if d['lang'] == 'en'), "No description.")
                    results_list.append({
                        "id": cve_id,
                        "description": en_desc
                    })
            else:
                logger.warning(f"[NVD] API error: {response.status_code}")
        except Exception as e:
            logger.error(f"[NVD] Exception: {e}")

    if results_list:
        logger.info(f"[+] Found {len(results_list)} CVEs for {service_banner}")
        for r in results_list:
            logger.info(f"  - {r['id']}: {r['description']}")
    else:
        logger.info(f"[!] No CVEs found for {service_banner}")

    return results_list
