import os
import threading
import time
import numpy as np
import pygetwindow as gw
import scapy.all as scapy
import requests
import smtplib
from email.mime.text import MIMEText
from sklearn.ensemble import RandomForestClassifier
from pynput import keyboard
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, filedialog

# Global variables
data = []
monitoring_threads = []
monitoring_active = False
stop_event = threading.Event()

API_KEY = 'your virustotal api key'
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
EMAIL_USERNAME = 'your_email@gmail.com'
EMAIL_PASSWORD = 'your_password'
EMAIL_RECIPIENTS = ['recipient1@gmail.com', 'recipient2@gmail.com']


def train_ai_model():
    print("Training AI model...")
    sample_data = np.random.rand(100, 5)
    sample_labels = np.random.randint(2, size=100)
    model = RandomForestClassifier()
    model.fit(sample_data, sample_labels)
    print("[AI] Model trained successfully!")
    return model


def send_email(subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_USERNAME
    msg['To'] = ', '.join(EMAIL_RECIPIENTS)
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
            server.sendmail(EMAIL_USERNAME, EMAIL_RECIPIENTS, msg.as_string())
            print("[EMAIL] Alert email sent successfully!")
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")


def monitor_windows():
    while not stop_event.is_set():
        active_window = gw.getActiveWindow()
        if active_window:
            title = active_window.title
            print(f"[WINDOW] Active Window: {title}")
            data.append(f"[WINDOW] {title}")
        time.sleep(2)


def start_keylogger():
    def on_press(key):
        try:
            key_data = str(key.char)
        except AttributeError:
            key_data = str(key)
        print(f"[KEYSTROKE] {key_data}")
        data.append(f"[KEYSTROKE] {key_data}")

    def on_release(key):
        if stop_event.is_set():
            return False

    with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()


def monitor_network():
    def process_packet(packet):
        if packet.haslayer(scapy.IP):
            log = f"[NETWORK] {packet[scapy.IP].src} -> {packet[scapy.IP].dst}"
            print(log)
            data.append(log)

    while not stop_event.is_set():
        scapy.sniff(prn=process_packet, store=False, timeout=1)


def create_gui():
    def start_detection():
        global monitoring_active, stop_event

        if not monitoring_active:
            print("Starting Advanced Keylogger Detection Tool...")
            train_ai_model()
            monitoring_active = True
            stop_event.clear()
            monitoring_threads.clear()

            monitoring_threads.append(threading.Thread(target=monitor_windows, daemon=True))
            monitoring_threads.append(threading.Thread(target=start_keylogger, daemon=True))
            monitoring_threads.append(threading.Thread(target=monitor_network, daemon=True))

            for thread in monitoring_threads:
                thread.start()

            messagebox.showinfo("Info", "Monitoring Started")
        else:
            messagebox.showwarning("Warning", "Monitoring is already running!")

    def stop_detection():
        global monitoring_active, stop_event

        if monitoring_active:
            print("Stopping monitoring...")
            stop_event.set()
            monitoring_active = False
            for thread in monitoring_threads:
                thread.join(timeout=3)

            save_prompt = messagebox.askyesno("Save Log", "Do you want to save the log before exiting?")
            if save_prompt:
                save_log()

            messagebox.showinfo("Info", "Monitoring Stopped")
        else:
            messagebox.showwarning("Warning", "No monitoring is active!")

    def save_log():
        log_filename = f"monitoring_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(log_filename, 'w') as log_file:
            log_file.write("\t\t=== Monitoring Log ===\n")
            log_file.write(f"Generated on: {datetime.now()}\n\n")
            for entry in data:
                log_file.write(f"{entry}\n")
        messagebox.showinfo("Info", f"Log saved as {log_filename}")

    def scan_file_with_virustotal():
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        print(f"Scanning file: {file_path}")
        with open(file_path, 'rb') as file:
            files = {'file': (os.path.basename(file_path), file)}
            headers = {'x-apikey': API_KEY}
            response = requests.post('https://www.virustotal.com/api/v3/files', files=files, headers=headers)

            if response.status_code == 200:
                analysis_url = response.json()['data']['links']['self']
                print(f"File uploaded successfully. Check results here: {analysis_url}")
                messagebox.showinfo("File Uploaded", f"Check results: {analysis_url}")
            else:
                print("Error uploading file to VirusTotal")
                messagebox.showerror("Error", "VirusTotal upload failed")

    root = tk.Tk()
    root.title("Advanced Keylogger Detection Tool")
    root.geometry("400x400")
    tk.Label(root, text="Click the buttons to manage monitoring").pack(pady=20)

    tk.Button(root, text="Start Monitoring", command=start_detection).pack(pady=10)
    tk.Button(root, text="Stop Monitoring", command=stop_detection).pack(pady=10)
    tk.Button(root, text="Save Log", command=save_log).pack(pady=10)
    tk.Button(root, text="Scan File with VirusTotal", command=scan_file_with_virustotal).pack(pady=10)

    root.mainloop()


if __name__ == "__main__":
    create_gui()
