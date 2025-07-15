import streamlit as st
import os
import psutil
from datetime import datetime
from .config import APP_VERSION, QUARANTINE_DIR
from .scanner import scan_directory
from .monitor import SystemMonitor

# Set page config as the first Streamlit command
st.set_page_config(page_title="SecureGuard Antivirus", layout="wide", initial_sidebar_state="expanded")

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

def display_dashboard():
    """Display the main dashboard"""
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

def display_scan_center():
    """Display the scan center interface"""
    st.markdown("<h1 class='title'>🔍 Scan Center</h1>", unsafe_allow_html=True)
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("Quick Scan", key="quick"):
            with st.spinner("Performing Quick Scan..."):
                results = scan_directory(os.path.join(os.environ.get('USERPROFILE'), 'Downloads'))
                display_scan_results(results)
    
    with col2:
        if st.button("Full Scan", key="full"):
            with st.spinner("Performing Full Scan..."):
                results = scan_directory(os.environ.get('USERPROFILE'))
                display_scan_results(results)
    
    with col3:
        if st.button("System Scan", key="system"):
            with st.spinner("Performing System Scan..."):
                results = scan_directory(os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32'))
                display_scan_results(results)
    
    with col4:
        path = st.text_input("Custom Path", placeholder="e.g., C:/Folder", label_visibility="visible")
        if st.button("Custom Scan", key="custom") and path:
            with st.spinner("Performing Custom Scan..."):
                results = scan_directory(path)
                display_scan_results(results)

def display_scan_results(results):
    """Display scan results"""
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

def display_quarantine():
    """Display quarantine management interface"""
    st.markdown("<h1 class='title'>🗑️ Quarantine Manager</h1>", unsafe_allow_html=True)
    for file in os.listdir(QUARANTINE_DIR):
        col1, col2, col3 = st.columns([3, 1, 1])
        col1.write(f"📄 {file}")
        if col2.button("Restore", key=f"r_{file}"):
            restore_file(file)
        if col3.button("Delete", key=f"d_{file}"):
            remove_file(file)

def display_system_tuneup():
    """Display system optimization interface"""
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

def main():
    """Main UI function"""
    st.sidebar.markdown("<h2 style='color: white;'>🔒 SecureGuard</h2>", unsafe_allow_html=True)
    options = ["Dashboard", "Scan Center", "Real-time Protection", "Quarantine", "System Tune-Up", "Signature Updates"]
    option = st.sidebar.radio("Navigation", options, format_func=lambda x: f"🛠️ {x}")
    st.sidebar.markdown(f"<p style='color: #a3bffa;'>Version {APP_VERSION}</p>", unsafe_allow_html=True)
    
    if option == "Dashboard":
        display_dashboard()
    elif option == "Scan Center":
        display_scan_center()
    elif option == "Real-time Protection":
        display_realtime_protection()
    elif option == "Quarantine":
        display_quarantine()
    elif option == "System Tune-Up":
        display_system_tuneup()
    elif option == "Signature Updates":
        display_signature_updates()

if __name__ == "__main__":
    main() 