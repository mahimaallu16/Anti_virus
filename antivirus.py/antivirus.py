import streamlit as st
import os
import psutil
import shutil
import time
import logging
import winreg
import subprocess
from datetime import datetime, timedelta
import threading
import json
from concurrent.futures import ThreadPoolExecutor
import queue
import re
import requests
from pathlib import Path

# Try to import scapy, but make it optional
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    st.warning("Network monitoring features are disabled. Install Npcap from https://npcap.com/ to enable them.")

# Set page config as the first Streamlit command
st.set_page_config(page_title="SecureGuard Antivirus", layout="wide", initial_sidebar_state="expanded")

# Import modular scanning/signature logic
from .scanner import FileScanner, ProcessMonitor, scan_directory
from .signatures import SignatureDatabase, get_file_hash
from .config import config, MAX_WORKERS, QUARANTINE_DIR, CACHE_DIR, SIGNATURE_DIR, SIGNATURE_TYPES

logging.basicConfig(filename=os.path.join(os.path.expanduser("~"), "antivirus.log"), 
                   level=logging.INFO, 
                   format="%(asctime)s - %(levelname)s - %(message)s")

def update_logs(message, level="INFO"):
    getattr(logging, level.lower())(message)
    st.session_state.setdefault('logs', []).append(f"{datetime.now()} - {level} - {message}")

# Custom CSS for Professional Look
st.markdown("""
    <style>
    .main {background-color: #f5f6f5; font-family: 'Segoe UI', sans-serif;}
    .sidebar .sidebar-content {background-color: #1a252f; color: white;}
    .stButton>button {background-color: #0078d4; color: white; border-radius: 8px; padding: 8px 16px; font-weight: 600;}
    .stButton>button:hover {background-color: #005ea2;}
    .title {color: #1a252f; font-size: 32px; font-weight: 700; text-align: center; margin-bottom: 20px;}
    .metric-box {background-color: #ffffff; padding: 15px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center;}
    .expander {background-color: #ffffff; border-radius: 8px; padding: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);}
    .status-bar {background-color: #e8ecef; padding: 10px; border-radius: 5px; font-size: 14px;}
    </style>
""", unsafe_allow_html=True)

# Configuration Management
def load_config():
    default_config = {"auto_update": True, "scan_interval": 3600, "threat_threshold": 50}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            update_logs("Config file corrupted, using defaults", "WARNING")
    with open(CONFIG_FILE, 'w') as f:
        json.dump(default_config, f)
    return default_config

config = load_config()

# Dashboard
def display_dashboard():
    st.markdown("<h1 class='title'>🛡️ SecureGuard Antivirus</h1>", unsafe_allow_html=True)
    st.markdown(f"<div class='status-bar'>Version {APP_VERSION} | Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>", unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("<div class='metric-box'>", unsafe_allow_html=True)
        st.metric("CPU Usage", f"{psutil.cpu_percent(interval=1)}%", delta=f"{psutil.cpu_percent(interval=1) - psutil.cpu_percent(interval=1, percpu=False):.1f}%")
        st.markdown("</div>", unsafe_allow_html=True)
    with col2:
        st.markdown("<div class='metric-box'>", unsafe_allow_html=True)
        ram = psutil.virtual_memory()
        st.metric("RAM Usage", f"{ram.percent}%", delta=f"{(ram.used - ram.total * 0.8) / (1024**3):.1f} GB")
        st.markdown("</div>", unsafe_allow_html=True)
    with col3:
        st.markdown("<div class='metric-box'>", unsafe_allow_html=True)
        st.metric("Disk Usage", f"{psutil.disk_usage('/').percent}%", delta=None)
        st.markdown("</div>", unsafe_allow_html=True)
    
    with st.expander("📜 Activity Log", expanded=True):
        st.markdown("<div class='expander'>", unsafe_allow_html=True)
        logs = st.session_state.get('logs', [])
        st.text_area("Recent Activity", "\n".join(logs[-10:]), height=150, disabled=True)
        st.markdown("</div>", unsafe_allow_html=True)

# Main UI
def main():
    st.sidebar.markdown("<h2 style='color: white;'>🔒 SecureGuard</h2>", unsafe_allow_html=True)
    options = ["Dashboard", "Scan Center", "Real-time Protection", "Quarantine", "System Tune-Up", "Signature Updates"]
    option = st.sidebar.radio("Navigation", options, format_func=lambda x: f"🛠️ {x}")
    st.sidebar.markdown(f"<p style='color: #a3bffa;'>Version {APP_VERSION}</p>", unsafe_allow_html=True)

    if option == "Signature Updates":
        st.markdown("<h1 class='title'>🔄 Signature Updates</h1>", unsafe_allow_html=True)
        if st.button("Update Signatures"):
            with st.spinner("Updating virus signatures..."):
                scanner = FileScanner()
                scanner.signature_db.update_signatures()
                st.success("Virus signatures updated successfully!")

    elif option == "Dashboard":
        display_dashboard()

    elif option == "Scan Center":
        st.markdown("<h1 class='title'>🔍 Scan Center</h1>", unsafe_allow_html=True)
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            if st.button("Quick Scan", key="quick"):
                with st.spinner("Performing Quick Scan..."):
                    results = quick_scan()
                    display_scan_results(results)
        with col2:
            if st.button("Full Scan", key="full"):
                with st.spinner("Performing Full Scan..."):
                    results = full_scan()
                    display_scan_results(results)
        with col3:
            if st.button("System Scan", key="system"):
                with st.spinner("Performing System Scan..."):
                    results = system_scan()
                    display_scan_results(results)
        with col4:
            path = st.text_input("Custom Path", placeholder="e.g., C:/Folder", label_visibility="visible")
            if st.button("Custom Scan", key="custom") and path:
                with st.spinner("Performing Custom Scan..."):
                    results = custom_scan(path)
                    display_scan_results(results)

    elif option == "Real-time Protection":
        st.markdown("<h1 class='title'>🛡️ Real-time Protection</h1>", unsafe_allow_html=True)
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Enable Protection", key="monitor"):
                start_monitoring()
        with col2:
            if st.button("Disable Protection", key="stop"):
                stop_monitoring()

    elif option == "Quarantine":
        st.markdown("<h1 class='title'>🗑️ Quarantine Manager</h1>", unsafe_allow_html=True)
        for file in os.listdir(QUARANTINE_DIR):
            col1, col2, col3 = st.columns([3, 1, 1])
            col1.write(f"📄 {file}")
            if col2.button("Restore", key=f"r_{file}"):
                restore_file(file)
            if col3.button("Delete", key=f"d_{file}"):
                remove_file(file)

    elif option == "System Tune-Up":
        st.markdown("<h1 class='title'>⚙️ System Tune-Up</h1>", unsafe_allow_html=True)
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Clear Junk Files", key="junk"):
                with st.spinner("Cleaning up..."):
                    clear_junk_files()
        with col2:
            if st.button("Optimize Memory", key="memory"):
                with st.spinner("Optimizing..."):
                    optimize_memory()

def display_scan_results(results):
    if results['processes']:
        st.write("**Suspicious Processes Detected:**")
        for p in results['processes']:
            col1, col2 = st.columns([3, 1])
            col1.write(f"- {p['info']['name']} (Score: {p['score']}, PID: {p['info']['pid']})")
            if col2.button("Quarantine", key=f"qp_{p['info']['pid']}"):
                quarantine_file(p['info']['exe'])
    if results['files']:
        st.write("**Suspicious Files Detected:**")
        for f in results['files']:
            col1, col2 = st.columns([3, 1])
            col1.write(f"- {f['path']} (Threat: {f['threat']}, Score: {f['score']})")
            if col2.button("Quarantine", key=f"qf_{f['path']}"):
                quarantine_file(f['path'])
    if not (results['processes'] or results['files']):
        st.success("System is clean!")
    st.info(f"Scan completed in {results['scan_time']:.2f} seconds")

if __name__ == "__main__":
    main()