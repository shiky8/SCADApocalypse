import argparse
import os
from utils.scadapass_updater import update_scadapass_local, load_scadapass_credentials
from plugins.plugin_manager import PluginManager
from utils.report import generate_json_report, generate_html_report
from utils.logger import setup_logger
from utils.cve_matcher import cve_search

logger = setup_logger()

def main():
    

    parser = argparse.ArgumentParser(prog='scadapocalypse', description="SCADApocalypse Toolkit — A SCADA-focused offensive security framework.",
        epilog='Developed by Mohamed Shahat | GitHub: @shiky8',)
    parser.add_argument('--version', action='version', version='SCADApocalypse v1.0')
    parser.add_argument('--target', required=True, help='Target IP address')
    parser.add_argument('--port', type=int, help='Set a custom port (optional)')
    parser.add_argument('--scada-system', help='Specify SCADA system name for targeted brute forcing')

    parser.add_argument('--cve', action='store_true', help='Run cve scanner , ex: --cve --scada-system openscada')

    parser.add_argument('--brute_http', action='store_true', help='Run http brute force attacks')
    parser.add_argument('--brute_ftp', action='store_true', help='Run ftp brute force attacks')
    parser.add_argument('--brute_ssh', action='store_true', help='Run ssh brute force attacks')
    parser.add_argument('--brute_telnet', action='store_true', help='Run telnet brute force attacks')
    parser.add_argument('--brute_snmp', action='store_true', help='Run snmp brute force attacks')
    parser.add_argument('--brute_vnc', action='store_true', help='Run vnc brute force attacks')
    

    parser.add_argument('--brute_requ', type=str, help='Set the POST request format for brute force attacks, when login use user=^USER^&pass=^PASS^')
    parser.add_argument('--brute_dir', type=str, help='Set the login URL path for brute force attacks')
    parser.add_argument('--brute_wordlist', type=str, help='Path to the wordlist file for brute force attacks')
    parser.add_argument('--brute_invaled_mass', type=str, help='Set the invalid login response message')

    parser.add_argument('--scan', type=str, help='Run scanners, ex. --scan all , --scan wincc_scanner')
    parser.add_argument('--list_scan', action='store_true', help='list all scanners')
    parser.add_argument('--tcp_port_scan', action='store_true', help='tcp port scan')
    parser.add_argument('--udp_port_scan', action='store_true', help='udp port scan')
    parser.add_argument('--detect_scada_scan', action='store_true', help='detect scada system via defualt port')

    parser.add_argument('--fuzz', type=str, help='Run fuzzers, ex. --fuzz all , --fuzz dnp3_fuzzer')
    parser.add_argument('--list_fuzz', action='store_true', help='list fuzzers')
    parser.add_argument('--list_payloads', action='store_true', help='list all payloads')
    parser.add_argument('--payload', type=str, help='set payload')

    parser.add_argument('--exploit', type=str, help='Run exploits , ex. --exploit all , --exploit bacnet_write_broadcast')
    parser.add_argument('--list_exploit', action='store_true', help='list all exploits')
    parser.add_argument('--user', type=str, help='username for login')
    parser.add_argument('--pwd', type=str, help='user password for login ')
    parser.add_argument('--lhost', type=str, help='listening host')
    parser.add_argument('--lport', type=int, help='listening port')
    args = parser.parse_args()

    target = args.target
    kwargs = {}
    if args.port is not None:
        kwargs['port'] = args.port
    if args.payload is not None:
        kwargs['payloads_file'] = args.payload
    if args.user is not None:
        kwargs['user'] = args.user
    if args.pwd is not None:
        kwargs['pwd'] = args.pwd
    if args.lhost is not None:
        kwargs['lhost'] = args.lhost
    if args.lport is not None:
        kwargs['lport'] = args.lport

    # ASCII BANNER
    banner = r"""
________  ________  ________  ________  ________  ________  ________  ________  ________  ___           ___    ___ ________  ________  _______      
|\   ____\|\   ____\|\   __  \|\   ___ \|\   __  \|\   __  \|\   __  \|\   ____\|\   __  \|\  \         |\  \  /  /|\   __  \|\   ____\|\  ___ \     
\ \  \___|\ \  \___|\ \  \|\  \ \  \_|\ \ \  \|\  \ \  \|\  \ \  \|\  \ \  \___|\ \  \|\  \ \  \        \ \  \/  / | \  \|\  \ \  \___|\ \   __/|    
 \ \_____  \ \  \    \ \   __  \ \  \ \\ \ \   __  \ \   ____\ \  \\\  \ \  \    \ \   __  \ \  \        \ \    / / \ \   ____\ \_____  \ \  \_|/__  
  \|____|\  \ \  \____\ \  \ \  \ \  \_\\ \ \  \ \  \ \  \___|\ \  \\\  \ \  \____\ \  \ \  \ \  \____    \/  /  /   \ \  \___|\|____|\  \ \  \_|\ \ 
    ____\_\  \ \_______\ \__\ \__\ \_______\ \__\ \__\ \__\    \ \_______\ \_______\ \__\ \__\ \_______\__/  / /      \ \__\     ____\_\  \ \_______\
   |\_________\|_______|\|__|\|__|\|_______|\|__|\|__|\|__|     \|_______|\|_______|\|__|\|__|\|_______|\___/ /        \|__|    |\_________\|_______|
   \|_________|                                                                                        \|___|/                  \|_________|         
                                                                                                                                                     
                                                SCADApocalypse Toolkit v1.0 — Dev by Mohamed Shahat (@shiky8)
    """

    print(banner)

    if os.path.exists("scadapass_local.csv"):
        scadapass_file = "scadapass_local.csv"
    else:
        scadapass_file = update_scadapass_local()
    # scadapass_creds = load_scadapass_credentials(scadapass_file) if scadapass_file else {}

    plugin_manager = PluginManager()
    plugin_manager.load_plugins()

    scan_results = {}
    brute_results = {}
    fuzz_results = {}
    exploit_results = {}
    cve_results = {}
    payload_dir = "payloads"

    if args.brute_http:
        from brute_force.brute_http import http_brute_force_with_scadapass
        result = http_brute_force_with_scadapass(target,
            args.brute_dir if args.brute_dir else "/login",
            args.brute_requ if args.brute_requ else "user=^USER^&pass=^PASS^",
            args.brute_invaled_mass if args.brute_invaled_mass else "Invalid credentials",
            args.brute_wordlist if args.brute_wordlist else scadapass_file,args.scada_system, **kwargs) 
        if result:
            user, pwd = result
        else:
            user, pwd = None, None

        brute_results['http'] = f"{user}:{pwd}" if user else "Failed"
        # user, pwd = http_brute_force_with_scadapass(target, "/login", "user=^USER^&pass=^PASS^", "Invalid credentials", scadapass_creds, args.scada_system)
        # brute_results['http'] = f"{user}:{pwd}" if user else "Failed"

    if args.brute_ftp:
        from brute_force.ftp_brute_force import ftp_brute_force_with_scadapass
        result = ftp_brute_force_with_scadapass(target, args.brute_wordlist if args.brute_wordlist else scadapass_file,args.scada_system, **kwargs)
        if result:
            user, pwd = result
        else:
            user, pwd = None, None

        brute_results['ftp'] = f"{user}:{pwd}" if user else "Failed"
    if args.brute_ssh:
        from brute_force.ssh_brute_force import ssh_brute_force_with_scadapass
        result = ssh_brute_force_with_scadapass(target,
         args.brute_wordlist if args.brute_wordlist else scadapass_file,args.scada_system, **kwargs)
        if result:
            user, pwd = result
        else:
            user, pwd = None, None

        brute_results['ssh'] = f"{user}:{pwd}" if user else "Failed"
    if args.brute_telnet:
        from brute_force.telnet_brute_force import telnet_brute_force_with_scadapass
        result = telnet_brute_force_with_scadapass(target, 
            args.brute_wordlist if args.brute_wordlist else scadapass_file,args.scada_system, **kwargs)
        if result:
            user, pwd = result
        else:
            user, pwd = None, None

        brute_results['telnet'] = f"{user}:{pwd}" if user else "Failed"
    if args.brute_snmp:
        from brute_force.snmp_brute_force import snmp_brute_force_with_scadapass
        result = snmp_brute_force_with_scadapass(target, 
            args.brute_wordlist if args.brute_wordlist else scadapass_file,args.scada_system, **kwargs)
        if result:
            user, pwd = result
        else:
            user, pwd = None, None

        brute_results['snmp'] = f"{user}:{pwd}" if user else "Failed"
    if args.brute_vnc:
        from brute_force.vnc_brute_force import vnc_brute_force_with_scadapass
        result = vnc_brute_force_with_scadapass(target, 
            args.brute_wordlist if args.brute_wordlist else scadapass_file,args.scada_system, **kwargs)
        if result:
            user, pwd = result
        else:
            user, pwd = None, None

        brute_results['vnc'] = f"{user}:{pwd}" if user else "Failed"

    if args.list_scan:
        print("_______________________________________________________________________________________________________")

        for scanner_name in plugin_manager.scanners.keys():
            logger.info(f"scanner name : {scanner_name}")
        print("_______________________________________________________________________________________________________")

   
    if args.scan:
        if args.scan.lower() =="all":
            for scanner_name in plugin_manager.scanners.keys():
                logger.info(f"Running scanner: {scanner_name}")
                result = plugin_manager.run_scanner(scanner_name, target, **kwargs)
                scan_results[scanner_name] = result
        else:
            scanner_name =  args.scan
            logger.info(f"Running scanner: {scanner_name}")
            result = plugin_manager.run_scanner(scanner_name, target, **kwargs)
            scan_results[scanner_name] = result

    if args.tcp_port_scan:
        scanner_name =  "port_scanner"
        scan_type = "tcp_scan"
        kwargs['scan_type'] = scan_type
        logger.info(f"Running scanner: {scanner_name}")
        result = plugin_manager.run_scanner(scanner_name, target, **kwargs)
        scan_results[scanner_name+" , "+scan_type] = result
    if args.udp_port_scan:
        scanner_name =  "port_scanner"
        scan_type = "udp_scan"
        kwargs['scan_type'] = scan_type
        logger.info(f"Running scanner: {scanner_name}")
        result = plugin_manager.run_scanner(scanner_name, target, **kwargs)
        scan_results[scanner_name+" , "+scan_type] = result
    if args.detect_scada_scan:
        scanner_name =  "port_scanner"
        scan_type = "detect_default_scada"
        kwargs['scan_type'] = scan_type
        logger.info(f"Running scanner: {scanner_name}")
        result = plugin_manager.run_scanner(scanner_name, target, **kwargs)
        scan_results[scanner_name+" , "+scan_type] = result

    

    if args.list_fuzz:
        print("_______________________________________________________________________________________________________")

        for fuzzer_name in plugin_manager.fuzzers.keys():
            logger.info(f"fuzzer name : {fuzzer_name}")
        print("_______________________________________________________________________________________________________")
    
    if args.list_payloads:
        print("_______________________________________________________________________________________________________")
        if os.path.exists(payload_dir) and os.path.isdir(payload_dir):
            payloads = [f for f in os.listdir(payload_dir) if os.path.isfile(os.path.join(payload_dir, f))]
        for payload in payloads:
            logger.info(f"payload name : {payload}")
        print("_______________________________________________________________________________________________________")



    if args.fuzz:
        if args.fuzz.lower() =="all":
            for fuzzer_name in plugin_manager.fuzzers.keys():
                logger.info(f"Running fuzzer: {fuzzer_name}")
                result = plugin_manager.run_fuzzer(fuzzer_name, target, **kwargs)
                fuzz_results[fuzzer_name] = result
        else:
            fuzzer_name =  args.fuzz
            logger.info(f"Running fuzzer: {fuzzer_name}")
            result = plugin_manager.run_fuzzer(fuzzer_name, target, **kwargs )
            fuzz_results[fuzzer_name] = result

    if args.list_exploit:
        print("_______________________________________________________________________________________________________")

        for exploit_name in plugin_manager.exploits.keys():
            logger.info(f"exploit name : {exploit_name}")
        print("_______________________________________________________________________________________________________")



    if args.exploit:
        if args.exploit.lower() =="all":
            for exploit_name in plugin_manager.exploits.keys():
                logger.info(f"Running all exploit: {exploit_name}")
                result = plugin_manager.run_exploit(exploit_name, target, **kwargs)
                exploit_results[exploit_name] = result
        else:
            exploit_name = args.exploit
            logger.info(f"Running 1 exploit: {exploit_name}")
            result = plugin_manager.run_exploit(exploit_name, target, **kwargs)
            exploit_results[exploit_name] = result

    if args.cve and args.scada_system:
        cve_results[args.scada_system] = cve_search(args.scada_system)

    if args.scan or args.exploit or args.fuzz or args.brute_http or args.brute_ftp or args.brute_ssh or args.brute_snmp or args.brute_telnet or args.brute_vnc or args.tcp_port_scan or  args.udp_port_scan or args.detect_scada_scan  or args.cve:
        json_report_path = generate_json_report(target, scan_results, brute_results, fuzz_results, cve_results, exploit_results)
        generate_html_report(json_report_path)

if __name__ == "__main__":
    main()