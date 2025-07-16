from utils.scadapass_updater import update_scadapass_local, load_scadapass_credentials
from plugins.plugin_manager import PluginManager
from utils.report import generate_json_report, generate_html_report
from utils.logger import setup_logger
from utils.cve_matcher import cve_search

from brute_force.brute_http import http_brute_force_with_scadapass
from brute_force.ftp_brute_force import ftp_brute_force_with_scadapass
from brute_force.ssh_brute_force import ssh_brute_force_with_scadapass
from brute_force.telnet_brute_force import telnet_brute_force_with_scadapass
from brute_force.snmp_brute_force import snmp_brute_force_with_scadapass
from brute_force.vnc_brute_force import vnc_brute_force_with_scadapass

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO
import logging
import sys
import argparse
import os

logger = setup_logger()

app = Flask(__name__)
# socketio = SocketIO(app, cors_allowed_origins="*")
socketio = SocketIO(app, async_mode='eventlet')


plugin_manager = PluginManager()
plugin_manager.load_plugins()

client_connected = False

# SocketIO logging handler
class SocketIOHandler(logging.Handler):
    def emit(self, record):
        log_entry = self.format(record)
        if client_connected:
            socketio.emit('log_message', {'data': log_entry})

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter('[%(levelname)s] %(asctime)s - %(message)s', datefmt='%H:%M:%S')

# Add SocketIO handler
socket_handler = SocketIOHandler()
socket_handler.setFormatter(formatter)
if not any(isinstance(h, SocketIOHandler) for h in logger.handlers):
    logger.addHandler(socket_handler)

# Also log to terminal
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

scan_results = {}
brute_results = {}
fuzz_results = {}
cve_results = {}
exploit_results = {}
oldtarget = ""

print(f"Go to http://127.0.0.1:5000/")

@app.route('/')
def index():
    return render_template('marketplace.html',
                           scanners=plugin_manager.scanners.keys(),
                           exploits=plugin_manager.exploits.keys(),
                           fuzzers=plugin_manager.fuzzers.keys())

@app.route('/run_scan', methods=['POST'])
def run_scan():
    data = request.json
    plugin = data.get("plugin")
    print(f"{plugin = }")
    target = data.get("target")
    oldtarget = target
    port = data.get("port")
    kwargs = {}
    if port:
        kwargs['port'] = int(port)

    socketio.emit('log_message', {'data': f"[INFO] [+] Starting scan with {plugin} on {target}:"})
    def task():
        try:
            result = plugin_manager.run_scanner(plugin, target, **kwargs)
            scan_results[plugin] = result
            socketio.emit('log_message', {'data': f"[INFO] [+] Scan completed for {target} using {plugin}"})
        except Exception as e:
            socketio.emit('log_message', {'data': f"[ERROR] Scan error: {str(e)}"})
    socketio.start_background_task(task)
    return '', 204

@app.route('/cve_scan', methods=['POST'])
def cve_scan():
    data = request.json
    scada_system = data.get("cvescada")
    print(f"{scada_system = }")
    
    socketio.emit('log_message', {'data': f"[INFO] [+] Starting scan with cve_search on {scada_system}:"})
    def task():
        try:
            result =  cve_search(scada_system)
            cve_results[scada_system] = result
            socketio.emit('log_message', {'data': f"[INFO] [+] cve_search  completed for {scada_system} "})
        except Exception as e:
            socketio.emit('log_message', {'data': f"[ERROR] cve_search error: {str(e)}"})
    socketio.start_background_task(task)
    return '', 204

@app.route('/run_exploit', methods=['POST'])
def run_exploit():
    data = request.json
    plugin = data.get("plugin")
    target = data.get("target")
    oldtarget = target
    port = data.get("port")
    kwargs = {}
    if port:
        kwargs['port'] = int(port)
    if data.get("user"):
        kwargs['user'] = data.get("user")
    if data.get("pwd"):
        kwargs['pwd'] = data.get("pwd")
    if data.get("lhost"):
        kwargs['lhost'] = data.get("lhost")
    if data.get("lport"):
        kwargs['lport'] = int(data.get("lport"))

    socketio.emit('log_message', {'data': f"[INFO] [+] Running exploit {plugin} on {target}"})
    def task():
        try:
            result = plugin_manager.run_exploit(plugin, target, **kwargs)
            exploit_results[plugin] = result
            socketio.emit('log_message', {'data': f"[INFO] [+] Exploit completed for {target} using {plugin}"})
        except Exception as e:
            socketio.emit('log_message', {'data': f"[ERROR] Exploit error: {str(e)}"})
    socketio.start_background_task(task)
    return '', 204

@app.route('/run_fuzzer', methods=['POST'])
def run_fuzzer():
    data = request.json
    plugin = data.get("plugin")
    target = data.get("target")
    oldtarget = target
    port = data.get("port")
    payload = data.get("payload")
    kwargs = {}
    if port:
        kwargs['port'] = int(port)
    if payload:
        kwargs['payloads_file'] = payload

    socketio.emit('log_message', {'data': f"[INFO] [+] Running fuzzer {plugin} on {target}"})
    def task():
        try:
            result = plugin_manager.run_fuzzer(plugin, target, **kwargs)
            fuzz_results[plugin] = result
            socketio.emit('log_message', {'data': f"[INFO] [+] Fuzzing completed for {target} using {plugin}"})
        except Exception as e:
            socketio.emit('log_message', {'data': f"[ERROR] Fuzzing error: {str(e)}"})
    socketio.start_background_task(task)
    return '', 204

@app.route('/run_brute', methods=['POST'])
def run_brute():
    data = request.json
    target = data.get("target")
    oldtarget = target
    port = data.get("port")
    scada_system = data.get("scada_system")
    brute_type = data.get("brute_type")
    brute_dir = data.get("brute_dir") or "/login"
    brute_requ = data.get("brute_requ") or "user=^USER^&pass=^PASS^"
    brute_invaled_mass = data.get("brute_invaled_mass") or "Invalid credentials"
    brute_wordlist = data.get("brute_wordlist") or "scadapass_local.csv"

    kwargs = {}
    if port:
        kwargs['port'] = int(port)

    
    socketio.emit('log_message', {'data': f"[INFO] [+] Starting brute force on {target}"})
    def task():

        func_map = {
            'http': lambda: http_brute_force_with_scadapass(target, brute_dir, brute_requ, brute_invaled_mass, brute_wordlist, scada_system, **kwargs),
            'ftp': lambda: ftp_brute_force_with_scadapass(target, brute_wordlist, scada_system, **kwargs),
            'ssh': lambda: ssh_brute_force_with_scadapass(target, brute_wordlist, scada_system, **kwargs),
            'telnet': lambda: telnet_brute_force_with_scadapass(target, brute_wordlist, scada_system, **kwargs),
            'snmp': lambda: snmp_brute_force_with_scadapass(target, brute_wordlist, scada_system, **kwargs),
            'vnc': lambda: vnc_brute_force_with_scadapass(target, brute_wordlist, scada_system, **kwargs),
        }

        if brute_type in func_map:
            try:
                result = func_map[brute_type]()
                user, pwd = result if result else (None, None)
                brute_results[brute_type] = f"{user}:{pwd}" if user else "Failed"
                socketio.emit('log_message', {'data': f"[INFO] [+] {brute_type.upper()} brute result: {user}:{pwd}" if user else f"[INFO] {brute_type.upper()} brute force failed"})
            except Exception as e:
                socketio.emit('log_message', {'data': f"[ERROR] {brute_type.upper()} brute force error: {str(e)}"})
        else:
            socketio.emit('log_message', {'data': f"[ERROR] Invalid brute_type provided: {brute_type}"})

    socketio.start_background_task(task)
    return '', 204

@app.route('/list_payloads')
def list_payloads():
    payload_dir = "payloads"
    payloads = []
    if os.path.exists(payload_dir):
        payloads = os.listdir(payload_dir)
    return jsonify(payloads)

@app.route('/results')
def get_results():
    def task():
        json_report_path = generate_json_report(oldtarget, scan_results, brute_results, fuzz_results, cve_results, exploit_results)
        socketio.emit('log_message', {'data': f"[INFO] [+]  JSON report saved to {json_report_path}"})
        html_repot_path =  generate_html_report(json_report_path)
        socketio.emit('log_message', {'data': f"[INFO] [+]  TML report saved to {html_repot_path}"})
    socketio.start_background_task(task)
    return jsonify({
        'scan_results': scan_results,
        'brute_results': brute_results,
        'fuzz_results': fuzz_results,
        'cve_results': cve_results,
        'exploit_results': exploit_results
    })

@socketio.on('connect')
def on_connect():
    global client_connected
    client_connected = True
    logger.info("Client connected to live log stream")
    # socketio.emit('log_message', {'data': '[INFO] Connected to live logs.\n'})

@socketio.on('disconnect')
def on_disconnect():
    global client_connected
    client_connected = False
    logger.info("Client disconnected from live log stream")
    # socketio.emit('log_message', {'data': '[INFO] Disconnected from live logs.'})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)
