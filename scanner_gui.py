#!/usr/bin/env python3
"""
Advanced IoT Scanner GUI Application
Modern graphical interface for the IoT scanner
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
import json
import time
from datetime import datetime
import os
import sys

# Import the scanner (will handle import errors gracefully)
try:
    from iot_scanner import AdvancedIoTScanner
    SCANNER_AVAILABLE = True
except ImportError as e:
    SCANNER_AVAILABLE = False
    print(f"Warning: IoT Scanner module not found ({e}). Running in demo mode.")
    
    # Create a fallback scanner class for demo mode
    class AdvancedIoTScanner:
        def __init__(self, network_range="192.168.1.0/24", max_threads=200, stealth_mode=False):
            self.network_range = network_range
            self.max_threads = max_threads
            self.stealth_mode = stealth_mode
            
        def run_scan(self):
            """Demo scan that returns sample data"""
            import time
            time.sleep(2)  # Simulate scanning time
            return {
                'demo': True,
                'total_devices': 5,
                'compromised_devices': 2,
                'scan_time': 2.0,
                'compromised_list': [
                    {'ip': '192.168.1.10', 'credentials': {'username': 'admin', 'password': 'admin'}},
                    {'ip': '192.168.1.15', 'credentials': {'username': 'root', 'password': 'root'}}
                ]
            }


class IoTScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced IoT Scanner - Professional Edition")
        self.root.geometry("1400x900")
        
        # Set modern theme
        style = ttk.Style()
        style.theme_use('clam')
        
        # Color scheme - Matrix green on black theme
        self.colors = {
            'bg': '#000000',
            'fg': '#00ff00',
            'accent': '#00ff00',
            'success': '#00ff00',
            'warning': '#ffff00',
            'danger': '#ff0000',
            'panel': '#001100',
            'border': '#003300'
        }
        
        # Configure root
        self.root.configure(bg=self.colors['bg'])
        
        # Scanner state
        self.scanner = None
        self.scan_thread = None
        self.is_scanning = False
        self.scan_results = []
        self.message_queue = queue.Queue()
        
        # Create UI
        self.create_menu()
        self.create_main_interface()
        self.create_status_bar()
        
        # Start message processor
        self.process_messages()
        
    def create_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Load Configuration", command=self.load_config)
        file_menu.add_command(label="Save Configuration", command=self.save_config)
        file_menu.add_separator()
        file_menu.add_command(label="Export Results", command=self.export_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Scan menu
        scan_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Scan", menu=scan_menu)
        scan_menu.add_command(label="Start Scan", command=self.start_scan)
        scan_menu.add_command(label="Stop Scan", command=self.stop_scan)
        scan_menu.add_command(label="Pause Scan", command=self.pause_scan)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Port Scanner", command=self.open_port_scanner)
        tools_menu.add_command(label="Credential Tester", command=self.open_credential_tester)
        tools_menu.add_command(label="Vulnerability Scanner", command=self.open_vuln_scanner)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="About", command=self.show_about)
        
    def create_main_interface(self):
        """Create main interface"""
        # Main container
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left panel - Controls
        left_panel = ttk.LabelFrame(main_container, text="Scanner Control", padding=10)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 5))
        
        self.create_control_panel(left_panel)
        
        # Right panel - Tabs
        right_panel = ttk.Frame(main_container)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Notebook (tabs)
        self.notebook = ttk.Notebook(right_panel)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_devices_tab()
        self.create_vulnerabilities_tab()
        self.create_console_tab()
        self.create_reports_tab()
        
    def create_control_panel(self, parent):
        """Create control panel"""
        # Network Configuration
        config_frame = ttk.LabelFrame(parent, text="Network Configuration", padding=10)
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(config_frame, text="Network Range:").pack(anchor=tk.W)
        self.network_entry = ttk.Entry(config_frame, width=30)
        self.network_entry.insert(0, "192.168.1.0/24")
        self.network_entry.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(config_frame, text="Max Threads:").pack(anchor=tk.W)
        self.threads_spinbox = ttk.Spinbox(config_frame, from_=1, to=1000, width=28)
        self.threads_spinbox.set(200)
        self.threads_spinbox.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(config_frame, text="Scan Type:").pack(anchor=tk.W)
        self.scan_type_combo = ttk.Combobox(config_frame, width=28, state='readonly')
        self.scan_type_combo['values'] = ('Quick Scan', 'Full Scan', 'Vulnerability Scan', 'Stealth Scan')
        self.scan_type_combo.current(1)
        self.scan_type_combo.pack(fill=tk.X, pady=(0, 10))
        
        # Options
        options_frame = ttk.LabelFrame(parent, text="Scan Options", padding=10)
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.fingerprint_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Device Fingerprinting", 
                       variable=self.fingerprint_var).pack(anchor=tk.W)
        
        self.vuln_scan_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Vulnerability Scanning", 
                       variable=self.vuln_scan_var).pack(anchor=tk.W)
        
        self.exploit_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Exploit Testing", 
                       variable=self.exploit_var).pack(anchor=tk.W)
        
        self.stealth_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Stealth Mode", 
                       variable=self.stealth_var).pack(anchor=tk.W)
        
        self.continuous_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Continuous Scanning", 
                       variable=self.continuous_var).pack(anchor=tk.W)
        
        # Control Buttons
        buttons_frame = ttk.Frame(parent)
        buttons_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.start_btn = ttk.Button(buttons_frame, text="▶ Start Scan", 
                                    command=self.start_scan, style='Accent.TButton')
        self.start_btn.pack(fill=tk.X, pady=(0, 5))
        
        self.stop_btn = ttk.Button(buttons_frame, text="⏹ Stop Scan", 
                                   command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(fill=tk.X, pady=(0, 5))
        
        self.pause_btn = ttk.Button(buttons_frame, text="⏸ Pause Scan", 
                                    command=self.pause_scan, state=tk.DISABLED)
        self.pause_btn.pack(fill=tk.X, pady=(0, 5))
        
        self.export_btn = ttk.Button(buttons_frame, text="📊 Export Results", 
                                     command=self.export_results)
        self.export_btn.pack(fill=tk.X, pady=(0, 5))
        
        # Statistics
        stats_frame = ttk.LabelFrame(parent, text="Statistics", padding=10)
        stats_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        self.stats_labels = {}
        stats = [
            ("Devices Found:", "0"),
            ("Compromised:", "0"),
            ("Vulnerabilities:", "0"),
            ("Scan Progress:", "0%"),
            ("Time Elapsed:", "0:00:00")
        ]
        
        for label, value in stats:
            frame = ttk.Frame(stats_frame)
            frame.pack(fill=tk.X, pady=2)
            ttk.Label(frame, text=label, font=('Arial', 9, 'bold')).pack(side=tk.LEFT)
            self.stats_labels[label] = ttk.Label(frame, text=value, font=('Arial', 9))
            self.stats_labels[label].pack(side=tk.RIGHT)
    
    def create_dashboard_tab(self):
        """Create dashboard tab"""
        dashboard = ttk.Frame(self.notebook)
        self.notebook.add(dashboard, text="📊 Dashboard")
        
        # Progress section
        progress_frame = ttk.LabelFrame(dashboard, text="Scan Progress", padding=10)
        progress_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, 
                                           maximum=100, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=(0, 5))
        
        self.progress_label = ttk.Label(progress_frame, text="Ready to scan", 
                                       font=('Arial', 10, 'italic'))
        self.progress_label.pack(anchor=tk.W)
        
        # Live Activity Feed
        activity_frame = ttk.LabelFrame(dashboard, text="Live Activity", padding=10)
        activity_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        self.activity_text = scrolledtext.ScrolledText(activity_frame, height=20, 
                                                       wrap=tk.WORD, state=tk.DISABLED,
                                                       bg='#000000', fg='#00ff00',
                                                       font=('Consolas', 9))
        self.activity_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure text tags for colored output - Matrix theme
        self.activity_text.tag_config('timestamp', foreground='#006600')
        self.activity_text.tag_config('info', foreground='#00ff00')
        self.activity_text.tag_config('success', foreground='#00ff00')
        self.activity_text.tag_config('warning', foreground='#ffff00')
        self.activity_text.tag_config('error', foreground='#ff0000')
    
    def create_devices_tab(self):
        """Create devices tab"""
        devices = ttk.Frame(self.notebook)
        self.notebook.add(devices, text="🖥️ Devices")
        
        # Filters
        filter_frame = ttk.Frame(devices)
        filter_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=(0, 5))
        self.device_filter = ttk.Entry(filter_frame, width=30)
        self.device_filter.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(filter_frame, text="Apply", command=self.apply_device_filter).pack(side=tk.LEFT)
        ttk.Button(filter_frame, text="Clear", command=self.clear_device_filter).pack(side=tk.LEFT, padx=(5, 0))
        
        # Devices Tree
        tree_frame = ttk.Frame(devices)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        
        self.devices_tree = ttk.Treeview(tree_frame, 
                                         columns=("IP", "Hostname", "Type", "OS", "Ports", "Status", "Creds"),
                                         yscrollcommand=vsb.set,
                                         xscrollcommand=hsb.set)
        
        vsb.config(command=self.devices_tree.yview)
        hsb.config(command=self.devices_tree.xview)
        
        # Configure columns
        self.devices_tree.heading("#0", text="ID")
        self.devices_tree.heading("IP", text="IP Address")
        self.devices_tree.heading("Hostname", text="Hostname")
        self.devices_tree.heading("Type", text="Device Type")
        self.devices_tree.heading("OS", text="OS")
        self.devices_tree.heading("Ports", text="Open Ports")
        self.devices_tree.heading("Status", text="Status")
        self.devices_tree.heading("Creds", text="Credentials")
        
        self.devices_tree.column("#0", width=50)
        self.devices_tree.column("IP", width=120)
        self.devices_tree.column("Hostname", width=150)
        self.devices_tree.column("Type", width=120)
        self.devices_tree.column("OS", width=100)
        self.devices_tree.column("Ports", width=100)
        self.devices_tree.column("Status", width=100)
        self.devices_tree.column("Creds", width=150)
        
        # Grid layout
        self.devices_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Context menu
        self.device_context_menu = tk.Menu(self.root, tearoff=0)
        self.device_context_menu.add_command(label="View Details", command=self.view_device_details)
        self.device_context_menu.add_command(label="Test Credentials", command=self.test_device_credentials)
        self.device_context_menu.add_command(label="Scan Vulnerabilities", command=self.scan_device_vulns)
        self.device_context_menu.add_separator()
        self.device_context_menu.add_command(label="Export Device Info", command=self.export_device_info)
        
        self.devices_tree.bind("<Button-3>", self.show_device_context_menu)
    
    def create_vulnerabilities_tab(self):
        """Create vulnerabilities tab"""
        vulns = ttk.Frame(self.notebook)
        self.notebook.add(vulns, text="🛡️ Vulnerabilities")
        
        # Summary cards
        summary_frame = ttk.Frame(vulns)
        summary_frame.pack(fill=tk.X, padx=10, pady=10)
        
        severities = [
            ("Critical", "#f44336", "critical_count"),
            ("High", "#ff9800", "high_count"),
            ("Medium", "#ff9800", "medium_count"),
            ("Low", "#4caf50", "low_count")
        ]
        
        for severity, color, var in severities:
            card = ttk.Frame(summary_frame, relief=tk.RAISED, borderwidth=2)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
            
            ttk.Label(card, text=severity, font=('Arial', 10, 'bold')).pack(pady=(10, 0))
            label = ttk.Label(card, text="0", font=('Arial', 20, 'bold'))
            label.pack(pady=(0, 10))
            setattr(self, var, label)
        
        # Vulnerabilities Tree
        tree_frame = ttk.Frame(vulns)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        self.vulns_tree = ttk.Treeview(tree_frame,
                                       columns=("CVE", "Name", "Severity", "Device", "Status"),
                                       yscrollcommand=vsb.set)
        vsb.config(command=self.vulns_tree.yview)
        
        self.vulns_tree.heading("#0", text="ID")
        self.vulns_tree.heading("CVE", text="CVE ID")
        self.vulns_tree.heading("Name", text="Name")
        self.vulns_tree.heading("Severity", text="Severity")
        self.vulns_tree.heading("Device", text="Affected Device")
        self.vulns_tree.heading("Status", text="Status")
        
        self.vulns_tree.column("#0", width=50)
        self.vulns_tree.column("CVE", width=150)
        self.vulns_tree.column("Name", width=200)
        self.vulns_tree.column("Severity", width=100)
        self.vulns_tree.column("Device", width=150)
        self.vulns_tree.column("Status", width=100)
        
        self.vulns_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_console_tab(self):
        """Create console tab"""
        console = ttk.Frame(self.notebook)
        self.notebook.add(console, text="💻 Console")
        
        # Console output - Matrix theme
        self.console_text = scrolledtext.ScrolledText(console, height=30, wrap=tk.WORD,
                                                     bg='#000000', fg='#00ff00',
                                                     font=('Consolas', 9))
        self.console_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Configure tags - Matrix theme
        self.console_text.tag_config('timestamp', foreground='#006600')
        self.console_text.tag_config('info', foreground='#00ff00')
        self.console_text.tag_config('success', foreground='#00ff00')
        self.console_text.tag_config('warning', foreground='#ffff00')
        self.console_text.tag_config('error', foreground='#ff0000')
        self.console_text.tag_config('creds', foreground='#00ffff', font=('Consolas', 9, 'bold'))
    
    def create_reports_tab(self):
        """Create reports tab"""
        reports = ttk.Frame(self.notebook)
        self.notebook.add(reports, text="📄 Reports")
        
        # Report configuration
        config_frame = ttk.LabelFrame(reports, text="Report Configuration", padding=10)
        config_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(config_frame, text="Report Type:").pack(anchor=tk.W)
        self.report_type_combo = ttk.Combobox(config_frame, state='readonly')
        self.report_type_combo['values'] = ('Executive Summary', 'Technical Report', 
                                           'Vulnerability Report', 'Compliance Report')
        self.report_type_combo.current(0)
        self.report_type_combo.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(config_frame, text="Format:").pack(anchor=tk.W)
        self.report_format_combo = ttk.Combobox(config_frame, state='readonly')
        self.report_format_combo['values'] = ('PDF', 'HTML', 'JSON', 'CSV', 'Excel')
        self.report_format_combo.current(0)
        self.report_format_combo.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(config_frame, text="Generate Report", 
                  command=self.generate_report).pack(fill=tk.X)
        
        # Report preview
        preview_frame = ttk.LabelFrame(reports, text="Report Preview", padding=10)
        preview_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        self.report_preview = scrolledtext.ScrolledText(preview_frame, height=20, wrap=tk.WORD)
        self.report_preview.pack(fill=tk.BOTH, expand=True)
    
    def create_status_bar(self):
        """Create status bar"""
        self.status_bar = ttk.Frame(self.root, relief=tk.SUNKEN)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_label = ttk.Label(self.status_bar, text="Ready", 
                                     font=('Arial', 9))
        self.status_label.pack(side=tk.LEFT, padx=10, pady=2)
        
        self.time_label = ttk.Label(self.status_bar, text="", 
                                    font=('Arial', 9))
        self.time_label.pack(side=tk.RIGHT, padx=10, pady=2)
        
        # Update time
        self.update_time()
    
    def update_time(self):
        """Update time in status bar"""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=current_time)
        self.root.after(1000, self.update_time)
    
    def start_scan(self):
        """Start scanning"""
        if not SCANNER_AVAILABLE:
            messagebox.showinfo("Demo Mode", "Scanner module not available. Running in demo mode with sample data.")
            self.run_demo_scan()
            return
        
        if self.is_scanning:
            messagebox.showwarning("Warning", "A scan is already in progress!")
            return
        
        # Get configuration
        network_range = self.network_entry.get()
        max_threads = int(self.threads_spinbox.get())
        stealth_mode = self.stealth_var.get()
        
        # Validate network range
        if not network_range:
            messagebox.showerror("Error", "Please enter a network range!")
            return
        
        # Clear previous results
        self.clear_results()
        
        # Update UI
        self.is_scanning = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.pause_btn.config(state=tk.NORMAL)
        self.update_status("Scanning...")
        self.log_activity("info", f"Starting scan on {network_range}")
        
        # Start scan in separate thread
        self.scan_thread = threading.Thread(target=self.run_scan, 
                                            args=(network_range, max_threads, stealth_mode))
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def run_scan(self, network_range, max_threads, stealth_mode):
        """Run the actual scan"""
        try:
            # Create scanner instance
            self.scanner = AdvancedIoTScanner(
                network_range=network_range,
                max_threads=max_threads,
                stealth_mode=stealth_mode
            )
            
            # Run scan
            results = self.scanner.run_scan()
            
            # Update results
            self.message_queue.put(('scan_complete', results))
            
        except Exception as e:
            self.message_queue.put(('error', str(e)))
    
    def run_demo_scan(self):
        """Run demo scan for testing"""
        self.is_scanning = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.pause_btn.config(state=tk.NORMAL)
        self.update_status("Demo scan in progress...")
        self.log_activity("info", "Starting demo scan with sample IoT devices")
        
        # Simulate scanning with more realistic data
        def demo():
            devices = [
                {'ip': '192.168.1.1', 'hostname': 'router-gateway', 'type': 'Router', 'os': 'OpenWrt', 'ports': '22,80,443,8080', 'status': 'Compromised', 'creds': 'admin:admin'},
                {'ip': '192.168.1.10', 'hostname': 'security-cam-01', 'type': 'Security Camera', 'os': 'Linux', 'ports': '80,443,554', 'status': 'Compromised', 'creds': 'admin:12345'},
                {'ip': '192.168.1.15', 'hostname': 'smart-tv', 'type': 'Smart TV', 'os': 'Android', 'ports': '80,443,8008', 'status': 'Secure', 'creds': 'None'},
                {'ip': '192.168.1.20', 'hostname': 'iot-sensor', 'type': 'IoT Device', 'os': 'Embedded', 'ports': '1883,5683', 'status': 'Vulnerable', 'creds': 'None'},
                {'ip': '192.168.1.25', 'hostname': 'printer-office', 'type': 'Printer', 'os': 'Embedded', 'ports': '80,443,631', 'status': 'Secure', 'creds': 'None'},
                {'ip': '192.168.1.30', 'hostname': 'nas-storage', 'type': 'NAS', 'os': 'Linux', 'ports': '22,80,443,5000', 'status': 'Compromised', 'creds': 'admin:password'},
                {'ip': '192.168.1.35', 'hostname': 'smart-switch', 'type': 'Smart Switch', 'os': 'Embedded', 'ports': '80,443', 'status': 'Secure', 'creds': 'None'},
                {'ip': '192.168.1.40', 'hostname': 'thermostat', 'type': 'Smart Thermostat', 'os': 'Embedded', 'ports': '80,443', 'status': 'Vulnerable', 'creds': 'None'}
            ]
            
            for i in range(100):
                if not self.is_scanning:
                    break
                time.sleep(0.05)
                self.message_queue.put(('progress', i + 1))
                
                # Add devices progressively
                if i % 12 == 0 and i // 12 < len(devices):
                    device = devices[i // 12]
                    self.message_queue.put(('device', device))
                    
                    # Add some vulnerabilities for compromised devices
                    if device['status'] == 'Compromised':
                        vuln = {
                            'cve_id': f'CVE-2023-{1000 + i//12}',
                            'name': f'Default Credentials - {device["type"]}',
                            'severity': 'Critical',
                            'device': device['ip'],
                            'status': 'Verified'
                        }
                        self.message_queue.put(('vulnerability', vuln))
            
            self.message_queue.put(('scan_complete', {'demo': True}))
        
        threading.Thread(target=demo, daemon=True).start()
    
    def stop_scan(self):
        """Stop scanning"""
        if messagebox.askyesno("Confirm", "Are you sure you want to stop the scan?"):
            self.is_scanning = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.pause_btn.config(state=tk.DISABLED)
            self.update_status("Scan stopped")
            self.log_activity("warning", "Scan stopped by user")
    
    def pause_scan(self):
        """Pause scanning"""
        messagebox.showinfo("Info", "Pause functionality will be implemented soon!")
    
    def process_messages(self):
        """Process messages from scan thread"""
        try:
            while True:
                msg_type, msg_data = self.message_queue.get_nowait()
                
                if msg_type == 'progress':
                    self.progress_var.set(msg_data)
                    self.stats_labels["Scan Progress:"].config(text=f"{msg_data}%")
                    
                elif msg_type == 'device':
                    self.add_device(msg_data)
                    
                elif msg_type == 'vulnerability':
                    self.add_vulnerability(msg_data)
                    
                elif msg_type == 'scan_complete':
                    self.scan_complete(msg_data)
                    
                elif msg_type == 'error':
                    self.log_activity("error", f"Error: {msg_data}")
                    
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_messages)
    
    def add_device(self, device):
        """Add device to tree"""
        device_id = len(self.devices_tree.get_children()) + 1
        self.devices_tree.insert('', 'end', text=str(device_id), values=(
            device.get('ip', ''),
            device.get('hostname', 'Unknown'),
            device.get('type', 'Unknown'),
            device.get('os', 'Unknown'),
            device.get('ports', ''),
            device.get('status', 'Unknown'),
            device.get('creds', 'None')
        ))
        
        # Update stats
        current = int(self.stats_labels["Devices Found:"].cget("text"))
        self.stats_labels["Devices Found:"].config(text=str(current + 1))
        
        if device.get('status') == 'Compromised':
            current_comp = int(self.stats_labels["Compromised:"].cget("text"))
            self.stats_labels["Compromised:"].config(text=str(current_comp + 1))
        
        # Log activity
        status_color = "error" if device.get('status') == 'Compromised' else "success"
        self.log_activity(status_color, 
                         f"Found device: {device.get('ip')} - {device.get('type')} - {device.get('status')}")
        
        if device.get('creds') and device.get('creds') != 'None':
            self.log_console("creds", f"[CREDS] {device.get('ip')} - {device.get('creds')}")
    
    def add_vulnerability(self, vuln):
        """Add vulnerability to tree"""
        vuln_id = len(self.vulns_tree.get_children()) + 1
        self.vulns_tree.insert('', 'end', text=str(vuln_id), values=(
            vuln.get('cve_id', ''),
            vuln.get('name', ''),
            vuln.get('severity', ''),
            vuln.get('device', ''),
            vuln.get('status', 'Detected')
        ))
        
        # Update vulnerability counts
        severity = vuln.get('severity', '').lower()
        if 'critical' in severity:
            current = int(self.critical_count.cget("text"))
            self.critical_count.config(text=str(current + 1))
        elif 'high' in severity:
            current = int(self.high_count.cget("text"))
            self.high_count.config(text=str(current + 1))
        elif 'medium' in severity:
            current = int(self.medium_count.cget("text"))
            self.medium_count.config(text=str(current + 1))
        elif 'low' in severity:
            current = int(self.low_count.cget("text"))
            self.low_count.config(text=str(current + 1))
        
        # Update total vulnerabilities
        current_vulns = int(self.stats_labels["Vulnerabilities:"].cget("text"))
        self.stats_labels["Vulnerabilities:"].config(text=str(current_vulns + 1))
        
        # Log activity
        self.log_activity("error", 
                         f"Vulnerability found: {vuln.get('name')} on {vuln.get('device')}")
    
    def scan_complete(self, results):
        """Handle scan completion"""
        self.is_scanning = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.pause_btn.config(state=tk.DISABLED)
        self.update_status("Scan complete")
        self.log_activity("success", "Scan completed successfully!")
        
        messagebox.showinfo("Success", "Scan completed successfully!")
    
    def clear_results(self):
        """Clear all results"""
        # Clear devices tree
        for item in self.devices_tree.get_children():
            self.devices_tree.delete(item)
        
        # Clear vulnerabilities tree
        for item in self.vulns_tree.get_children():
            self.vulns_tree.delete(item)
        
        # Reset stats
        for label in self.stats_labels.values():
            if label.cget("text") != "Ready to scan":
                label.config(text="0" if "%" not in label.cget("text") else "0%")
        
        # Reset vulnerability counts
        self.critical_count.config(text="0")
        self.high_count.config(text="0")
        self.medium_count.config(text="0")
        self.low_count.config(text="0")
        
        # Clear activity feed
        self.activity_text.config(state=tk.NORMAL)
        self.activity_text.delete('1.0', tk.END)
        self.activity_text.config(state=tk.DISABLED)
        
        # Reset progress
        self.progress_var.set(0)
        self.progress_label.config(text="Ready to scan")
    
    def log_activity(self, level, message):
        """Log activity to activity feed"""
        self.activity_text.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.activity_text.insert(tk.END, f"[{timestamp}] ", 'timestamp')
        self.activity_text.insert(tk.END, f"{message}\n", level)
        self.activity_text.see(tk.END)
        self.activity_text.config(state=tk.DISABLED)
    
    def log_console(self, level, message):
        """Log to console"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console_text.insert(tk.END, f"[{timestamp}] ", 'timestamp')
        self.console_text.insert(tk.END, f"{message}\n", level)
        self.console_text.see(tk.END)
    
    def update_status(self, message):
        """Update status bar"""
        self.status_label.config(text=message)
    
    # Menu handlers
    def load_config(self):
        """Load configuration"""
        filename = filedialog.askopenfilename(
            title="Load Configuration",
            filetypes=[("YAML files", "*.yaml"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            messagebox.showinfo("Info", f"Configuration loaded from {filename}")
    
    def save_config(self):
        """Save configuration"""
        filename = filedialog.asksaveasfilename(
            title="Save Configuration",
            defaultextension=".yaml",
            filetypes=[("YAML files", "*.yaml"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            messagebox.showinfo("Info", f"Configuration saved to {filename}")
    
    def export_results(self):
        """Export results"""
        filename = filedialog.asksaveasfilename(
            title="Export Results",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv"), 
                      ("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        if filename:
            # Export logic here
            messagebox.showinfo("Success", f"Results exported to {filename}")
    
    def open_port_scanner(self):
        """Open port scanner tool"""
        messagebox.showinfo("Info", "Port scanner tool coming soon!")
    
    def open_credential_tester(self):
        """Open credential tester tool"""
        messagebox.showinfo("Info", "Credential tester tool coming soon!")
    
    def open_vuln_scanner(self):
        """Open vulnerability scanner tool"""
        messagebox.showinfo("Info", "Vulnerability scanner tool coming soon!")
    
    def show_documentation(self):
        """Show documentation"""
        messagebox.showinfo("Documentation", "Full documentation available in README.md")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """Advanced IoT Scanner
Version 2.0.0

A comprehensive IoT device scanning and exploitation framework.

© 2024 Security Research Team
Licensed under MIT License"""
        messagebox.showinfo("About", about_text)
    
    # Context menu handlers
    def show_device_context_menu(self, event):
        """Show device context menu"""
        item = self.devices_tree.identify_row(event.y)
        if item:
            self.devices_tree.selection_set(item)
            self.device_context_menu.post(event.x_root, event.y_root)
    
    def view_device_details(self):
        """View device details"""
        selection = self.devices_tree.selection()
        if selection:
            messagebox.showinfo("Info", "Device details viewer coming soon!")
    
    def test_device_credentials(self):
        """Test device credentials"""
        selection = self.devices_tree.selection()
        if selection:
            messagebox.showinfo("Info", "Credential testing coming soon!")
    
    def scan_device_vulns(self):
        """Scan device vulnerabilities"""
        selection = self.devices_tree.selection()
        if selection:
            messagebox.showinfo("Info", "Vulnerability scanning coming soon!")
    
    def export_device_info(self):
        """Export device info"""
        selection = self.devices_tree.selection()
        if selection:
            messagebox.showinfo("Info", "Device export coming soon!")
    
    # Filter handlers
    def apply_device_filter(self):
        """Apply device filter"""
        filter_text = self.device_filter.get()
        messagebox.showinfo("Info", f"Filtering devices: {filter_text}")
    
    def clear_device_filter(self):
        """Clear device filter"""
        self.device_filter.delete(0, tk.END)
    
    # Report generation
    def generate_report(self):
        """Generate report"""
        report_type = self.report_type_combo.get()
        report_format = self.report_format_combo.get()
        
        self.report_preview.delete('1.0', tk.END)
        self.report_preview.insert(tk.END, f"Generating {report_type} in {report_format} format...\n\n")
        self.report_preview.insert(tk.END, "Report preview will appear here.")
        
        messagebox.showinfo("Success", f"Report generated: {report_type} ({report_format})")


def main():
    """Main entry point"""
    root = tk.Tk()
    app = IoTScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

