import os
import platform
import threading
import time
import numpy as np
import pandas as pd
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

data = []
label = []
monitoring_threads = []
monitoring_active = False
API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
EMAIL_USERNAME = 'your_email@gmail.com'
EMAIL_PASSWORD = 'your_password'
EMAIL_RECIPIENTS = ['recipient1@gmail.com', 'recipient2@gmail.com', 'recipient3@gmail.com', 'recipient4@gmail.com']


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
    while monitoring_active:
        active_window = gw.getActiveWindow()
        if active_window:
            print(f"[WINDOW] Active Window: {active_window.title}")
        time.sleep(2)


def on_press(key):
    try:
        key_data = str(key.char)
    except AttributeError:
        key_data = str(key)
    print(f"[KEYSTROKE] {key_data}")
    data.append(key_data)

def start_keylogger():
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()


def monitor_network():
    def process_packet(packet):
        if packet.haslayer(scapy.IP):
            print(f"[NETWORK] {packet[scapy.IP].src} -> {packet[scapy.IP].dst}")
    scapy.sniff(prn=process_packet, store=False)



def create_gui():
    def start_detection():
        global monitoring_active
        if not monitoring_active:
            print("Starting Advanced Keylogger Detection Tool...")
            model = train_ai_model()
            monitoring_active = True
            monitoring_threads.append(threading.Thread(target=monitor_windows))
            monitoring_threads.append(threading.Thread(target=start_keylogger))
            monitoring_threads.append(threading.Thread(target=monitor_network))
            for thread in monitoring_threads:
                thread.start()
            messagebox.showinfo("Info", "Monitoring Started")
        else:
            messagebox.showwarning("Warning", "Monitoring is already running!")

    def stop_detection():
        global monitoring_active
        if monitoring_active:
            monitoring_active = False
            print("Stopping monitoring...")
            save_prompt = messagebox.askyesno("Save Log", "Do you want to save the log before exiting?")
            if save_prompt:
                save_log()
            root.quit()
        else:
            messagebox.showwarning("Warning", "No monitoring is active!")

    def save_log():
        log_filename = f"monitoring_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(log_filename, 'w') as log_file:
            log_file.write("=== Monitoring Log ===\n")
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
                messagebox.showinfo("File Uploaded", f"File uploaded successfully. Check results here: {analysis_url}")
            else:
                print("Error uploading file to VirusTotal")
                messagebox.showerror("Error", "Error uploading file to VirusTotal")

    global root
    root = tk.Tk()
    root.title("Advanced Keylogger Detection Tool")
    root.geometry("400x400")
    label = tk.Label(root, text="Click the buttons to manage monitoring")
    label.pack(pady=20)

    start_button = tk.Button(root, text="Start Monitoring", command=start_detection)
    start_button.pack(pady=10)

    stop_button = tk.Button(root, text="Stop Monitoring", command=stop_detection)
    stop_button.pack(pady=10)

    save_button = tk.Button(root, text="Save Log", command=save_log)
    save_button.pack(pady=10)

    scan_button = tk.Button(root, text="Scan File with VirusTotal", command=scan_file_with_virustotal)
    scan_button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
