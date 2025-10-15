#!/usr/bin/env python3
"""
Advanced IoT Scanner Web Dashboard
Real-time monitoring and control interface
"""

import dash
from dash import dcc, html, Input, Output, State, dash_table
import plotly.graph_objs as go
import plotly.express as px
import pandas as pd
import sqlite3
import json
import threading
import time
from datetime import datetime, timedelta
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IoTScannerDashboard:
    def __init__(self, database_path="iot_devices.db"):
        self.db_path = database_path
        self.app = dash.Dash(__name__)
        self.setup_layout()
        self.setup_callbacks()
        
    def setup_layout(self):
        """Setup the dashboard layout"""
        self.app.layout = html.Div([
            # Header
            html.Div([
                html.H1("Advanced IoT Scanner Dashboard", className="header-title"),
                html.Div([
                    html.Span("Status: ", className="status-label"),
                    html.Span("Running", id="scanner-status", className="status-running"),
                    html.Span("Last Update: ", className="last-update-label"),
                    html.Span(id="last-update", className="last-update-time")
                ], className="header-info")
            ], className="header"),
            
            # Control Panel
            html.Div([
                html.H3("Scanner Control"),
                html.Div([
                    html.Button("Start Scan", id="start-scan-btn", className="btn btn-primary"),
                    html.Button("Stop Scan", id="stop-scan-btn", className="btn btn-danger"),
                    html.Button("Pause Scan", id="pause-scan-btn", className="btn btn-warning"),
                    html.Button("Export Results", id="export-btn", className="btn btn-success")
                ], className="control-buttons"),
                html.Div([
                    html.Label("Network Range:"),
                    dcc.Input(id="network-range", value="192.168.1.0/24", type="text"),
                    html.Label("Max Threads:"),
                    dcc.Input(id="max-threads", value=200, type="number", min=1, max=1000),
                    html.Label("Scan Type:"),
                    dcc.Dropdown(
                        id="scan-type",
                        options=[
                            {'label': 'Quick Scan', 'value': 'quick'},
                            {'label': 'Full Scan', 'value': 'full'},
                            {'label': 'Vulnerability Scan', 'value': 'vuln'},
                            {'label': 'Stealth Scan', 'value': 'stealth'}
                        ],
                        value='full'
                    )
                ], className="scan-config")
            ], className="control-panel"),
            
            # Statistics Cards
            html.Div([
                html.Div([
                    html.H4(id="total-devices", children="0"),
                    html.P("Total Devices")
                ], className="stat-card"),
                html.Div([
                    html.H4(id="compromised-devices", children="0"),
                    html.P("Compromised Devices")
                ], className="stat-card"),
                html.Div([
                    html.H4(id="vulnerabilities-found", children="0"),
                    html.P("Vulnerabilities Found")
                ], className="stat-card"),
                html.Div([
                    html.H4(id="scan-progress", children="0%"),
                    html.P("Scan Progress")
                ], className="stat-card")
            ], className="stats-grid"),
            
            # Main Content Tabs
            dcc.Tabs(id="main-tabs", value="overview", children=[
                dcc.Tab(label="Overview", value="overview"),
                dcc.Tab(label="Devices", value="devices"),
                dcc.Tab(label="Vulnerabilities", value="vulnerabilities"),
                dcc.Tab(label="Network Map", value="network-map"),
                dcc.Tab(label="Reports", value="reports"),
                dcc.Tab(label="Settings", value="settings")
            ]),
            
            # Tab Content
            html.Div(id="tab-content"),
            
            # Auto-refresh interval
            dcc.Interval(
                id='interval-component',
                interval=5*1000,  # Update every 5 seconds
                n_intervals=0
            )
        ])
        
    def setup_callbacks(self):
        """Setup dashboard callbacks"""
        
        @self.app.callback(
            [Output('tab-content', 'children'),
             Output('total-devices', 'children'),
             Output('compromised-devices', 'children'),
             Output('vulnerabilities-found', 'children'),
             Output('scan-progress', 'children'),
             Output('last-update', 'children')],
            [Input('main-tabs', 'value'),
             Input('interval-component', 'n_intervals')]
        )
        def update_dashboard(active_tab, n_intervals):
            # Get current statistics
            stats = self.get_statistics()
            
            # Update tab content
            if active_tab == "overview":
                content = self.create_overview_tab()
            elif active_tab == "devices":
                content = self.create_devices_tab()
            elif active_tab == "vulnerabilities":
                content = self.create_vulnerabilities_tab()
            elif active_tab == "network-map":
                content = self.create_network_map_tab()
            elif active_tab == "reports":
                content = self.create_reports_tab()
            elif active_tab == "settings":
                content = self.create_settings_tab()
            else:
                content = html.Div("Unknown tab")
            
            return (content, 
                   stats['total_devices'],
                   stats['compromised_devices'],
                   stats['vulnerabilities_found'],
                   f"{stats['scan_progress']}%",
                   datetime.now().strftime("%H:%M:%S"))
        
        @self.app.callback(
            Output('scanner-status', 'children'),
            [Input('interval-component', 'n_intervals')]
        )
        def update_scanner_status(n_intervals):
            # Check scanner status from database or process
            return "Running"  # This would check actual scanner status
        
    def create_overview_tab(self):
        """Create overview tab content"""
        return html.Div([
            # Real-time charts
            html.Div([
                html.Div([
                    html.H4("Scan Progress Over Time"),
                    dcc.Graph(id="scan-progress-chart")
                ], className="chart-container"),
                html.Div([
                    html.H4("Device Types Distribution"),
                    dcc.Graph(id="device-types-chart")
                ], className="chart-container")
            ], className="charts-row"),
            
            # Recent activity
            html.Div([
                html.H4("Recent Activity"),
                html.Div(id="recent-activity", className="activity-feed")
            ], className="activity-section"),
            
            # Top vulnerabilities
            html.Div([
                html.H4("Top Vulnerabilities"),
                html.Div(id="top-vulnerabilities", className="vuln-list")
            ], className="vulnerabilities-section")
        ])
    
    def create_devices_tab(self):
        """Create devices tab content"""
        devices_data = self.get_devices_data()
        
        return html.Div([
            # Device filters
            html.Div([
                html.Label("Filter by Device Type:"),
                dcc.Dropdown(
                    id="device-type-filter",
                    options=[
                        {'label': 'All', 'value': 'all'},
                        {'label': 'Router', 'value': 'Router'},
                        {'label': 'Security Camera', 'value': 'Security Camera'},
                        {'label': 'IoT Device', 'value': 'IoT Device'},
                        {'label': 'Network Device', 'value': 'Network Device'}
                    ],
                    value='all'
                ),
                html.Label("Filter by Status:"),
                dcc.Dropdown(
                    id="device-status-filter",
                    options=[
                        {'label': 'All', 'value': 'all'},
                        {'label': 'Compromised', 'value': 'compromised'},
                        {'label': 'Secure', 'value': 'secure'},
                        {'label': 'Vulnerable', 'value': 'vulnerable'}
                    ],
                    value='all'
                )
            ], className="device-filters"),
            
            # Devices table
            dash_table.DataTable(
                id='devices-table',
                columns=[
                    {"name": "IP Address", "id": "ip"},
                    {"name": "Hostname", "id": "hostname"},
                    {"name": "Device Type", "id": "device_type"},
                    {"name": "Vendor", "id": "vendor"},
                    {"name": "Status", "id": "status"},
                    {"name": "Open Ports", "id": "open_ports"},
                    {"name": "Vulnerabilities", "id": "vulnerabilities"},
                    {"name": "Last Seen", "id": "last_seen"}
                ],
                data=devices_data,
                sort_action="native",
                filter_action="native",
                page_action="native",
                page_current=0,
                page_size=20,
                style_cell={'textAlign': 'left'},
                style_header={'backgroundColor': 'rgb(230, 230, 230)', 'fontWeight': 'bold'},
                style_data_conditional=[
                    {
                        'if': {'filter_query': '{status} = compromised'},
                        'backgroundColor': '#ffebee',
                        'color': 'black',
                    },
                    {
                        'if': {'filter_query': '{status} = vulnerable'},
                        'backgroundColor': '#fff3e0',
                        'color': 'black',
                    }
                ]
            )
        ])
    
    def create_vulnerabilities_tab(self):
        """Create vulnerabilities tab content"""
        vuln_data = self.get_vulnerabilities_data()
        
        return html.Div([
            # Vulnerability summary
            html.Div([
                html.Div([
                    html.H4("Critical", className="vuln-critical"),
                    html.H3(id="critical-count", children="0")
                ], className="vuln-summary-card"),
                html.Div([
                    html.H4("High", className="vuln-high"),
                    html.H3(id="high-count", children="0")
                ], className="vuln-summary-card"),
                html.Div([
                    html.H4("Medium", className="vuln-medium"),
                    html.H3(id="medium-count", children="0")
                ], className="vuln-summary-card"),
                html.Div([
                    html.H4("Low", className="vuln-low"),
                    html.H3(id="low-count", children="0")
                ], className="vuln-summary-card")
            ], className="vuln-summary"),
            
            # Vulnerabilities table
            dash_table.DataTable(
                id='vulnerabilities-table',
                columns=[
                    {"name": "CVE ID", "id": "cve_id"},
                    {"name": "Name", "id": "name"},
                    {"name": "Severity", "id": "severity"},
                    {"name": "Description", "id": "description"},
                    {"name": "Affected Devices", "id": "affected_devices"},
                    {"name": "Verified", "id": "verified"},
                    {"name": "First Detected", "id": "first_detected"}
                ],
                data=vuln_data,
                sort_action="native",
                filter_action="native",
                page_action="native",
                page_current=0,
                page_size=20,
                style_cell={'textAlign': 'left'},
                style_header={'backgroundColor': 'rgb(230, 230, 230)', 'fontWeight': 'bold'},
                style_data_conditional=[
                    {
                        'if': {'filter_query': '{severity} = Critical'},
                        'backgroundColor': '#ffebee',
                        'color': 'black',
                    },
                    {
                        'if': {'filter_query': '{severity} = High'},
                        'backgroundColor': '#fff3e0',
                        'color': 'black',
                    },
                    {
                        'if': {'filter_query': '{severity} = Medium'},
                        'backgroundColor': '#fff8e1',
                        'color': 'black',
                    }
                ]
            )
        ])
    
    def create_network_map_tab(self):
        """Create network map tab content"""
        return html.Div([
            html.H4("Network Topology Map"),
            dcc.Graph(
                id="network-map",
                figure=self.create_network_map_figure()
            ),
            html.Div([
                html.Label("Map Type:"),
                dcc.Dropdown(
                    id="map-type",
                    options=[
                        {'label': 'Physical Topology', 'value': 'physical'},
                        {'label': 'Logical Topology', 'value': 'logical'},
                        {'label': 'Security Zones', 'value': 'security'},
                        {'label': 'Vulnerability Map', 'value': 'vulnerability'}
                    ],
                    value='physical'
                )
            ], className="map-controls")
        ])
    
    def create_reports_tab(self):
        """Create reports tab content"""
        return html.Div([
            html.H4("Generate Reports"),
            html.Div([
                html.Label("Report Type:"),
                dcc.Dropdown(
                    id="report-type",
                    options=[
                        {'label': 'Executive Summary', 'value': 'executive'},
                        {'label': 'Technical Report', 'value': 'technical'},
                        {'label': 'Vulnerability Report', 'value': 'vulnerability'},
                        {'label': 'Compliance Report', 'value': 'compliance'},
                        {'label': 'Custom Report', 'value': 'custom'}
                    ],
                    value='executive'
                ),
                html.Label("Format:"),
                dcc.Dropdown(
                    id="report-format",
                    options=[
                        {'label': 'PDF', 'value': 'pdf'},
                        {'label': 'HTML', 'value': 'html'},
                        {'label': 'JSON', 'value': 'json'},
                        {'label': 'CSV', 'value': 'csv'}
                    ],
                    value='pdf'
                ),
                html.Button("Generate Report", id="generate-report-btn", className="btn btn-primary")
            ], className="report-config"),
            
            # Report history
            html.Div([
                html.H4("Report History"),
                html.Div(id="report-history", className="report-list")
            ], className="report-history")
        ])
    
    def create_settings_tab(self):
        """Create settings tab content"""
        return html.Div([
            html.H4("Scanner Configuration"),
            html.Div([
                html.Label("Default Network Range:"),
                dcc.Input(id="default-network", value="192.168.1.0/24", type="text"),
                html.Label("Default Max Threads:"),
                dcc.Input(id="default-threads", value=200, type="number"),
                html.Label("Scan Timeout (seconds):"),
                dcc.Input(id="scan-timeout", value=3, type="number"),
                html.Label("Enable Stealth Mode:"),
                dcc.Checklist(
                    id="stealth-mode",
                    options=[{'label': 'Enable', 'value': 'enable'}],
                    value=[]
                )
            ], className="scanner-settings"),
            
            html.H4("Notification Settings"),
            html.Div([
                html.Label("Email Notifications:"),
                dcc.Checklist(
                    id="email-notifications",
                    options=[{'label': 'Enable', 'value': 'enable'}],
                    value=[]
                ),
                html.Label("Email Address:"),
                dcc.Input(id="email-address", type="email"),
                html.Label("Slack Notifications:"),
                dcc.Checklist(
                    id="slack-notifications",
                    options=[{'label': 'Enable', 'value': 'enable'}],
                    value=[]
                ),
                html.Label("Slack Webhook URL:"),
                dcc.Input(id="slack-webhook", type="url")
            ], className="notification-settings"),
            
            html.Button("Save Settings", id="save-settings-btn", className="btn btn-success")
        ])
    
    def create_network_map_figure(self):
        """Create network map visualization"""
        # This would create an interactive network topology map
        # For now, return a simple scatter plot
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=[1, 2, 3, 4, 5],
            y=[1, 2, 3, 4, 5],
            mode='markers+text',
            text=['Router', 'Camera', 'IoT Device', 'Server', 'Switch'],
            textposition="top center",
            marker=dict(size=20, color=['red', 'orange', 'yellow', 'green', 'blue'])
        ))
        fig.update_layout(
            title="Network Topology Map",
            xaxis_title="X Coordinate",
            yaxis_title="Y Coordinate",
            showlegend=False
        )
        return fig
    
    def get_statistics(self):
        """Get current scanner statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get total devices
            cursor.execute("SELECT COUNT(*) FROM devices")
            total_devices = cursor.fetchone()[0]
            
            # Get compromised devices
            cursor.execute("SELECT COUNT(*) FROM devices WHERE status = 'compromised'")
            compromised_devices = cursor.fetchone()[0]
            
            # Get vulnerabilities found
            cursor.execute("SELECT COUNT(*) FROM exploits WHERE success = 1")
            vulnerabilities_found = cursor.fetchone()[0]
            
            # Get scan progress (this would be calculated based on current scan)
            scan_progress = 75  # Placeholder
            
            conn.close()
            
            return {
                'total_devices': total_devices,
                'compromised_devices': compromised_devices,
                'vulnerabilities_found': vulnerabilities_found,
                'scan_progress': scan_progress
            }
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {
                'total_devices': 0,
                'compromised_devices': 0,
                'vulnerabilities_found': 0,
                'scan_progress': 0
            }
    
    def get_devices_data(self):
        """Get devices data for table"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT ip, hostname, device_type, vendor, status, 
                       open_ports, vulnerabilities, last_seen
                FROM devices
                ORDER BY last_seen DESC
            """)
            
            devices = cursor.fetchall()
            conn.close()
            
            return [
                {
                    'ip': device[0],
                    'hostname': device[1] or 'Unknown',
                    'device_type': device[2] or 'Unknown',
                    'vendor': device[3] or 'Unknown',
                    'status': device[4] or 'Unknown',
                    'open_ports': device[5] or 'None',
                    'vulnerabilities': device[6] or 'None',
                    'last_seen': device[7] or 'Unknown'
                }
                for device in devices
            ]
        except Exception as e:
            logger.error(f"Error getting devices data: {e}")
            return []
    
    def get_vulnerabilities_data(self):
        """Get vulnerabilities data for table"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT device_ip, exploit_name, success, output, timestamp
                FROM exploits
                WHERE success = 1
                ORDER BY timestamp DESC
            """)
            
            exploits = cursor.fetchall()
            conn.close()
            
            return [
                {
                    'cve_id': exploit[1],
                    'name': exploit[1],
                    'severity': 'High',  # This would be determined from the exploit
                    'description': exploit[3][:100] + '...' if len(exploit[3]) > 100 else exploit[3],
                    'affected_devices': exploit[0],
                    'verified': 'Yes' if exploit[2] else 'No',
                    'first_detected': exploit[4]
                }
                for exploit in exploits
            ]
        except Exception as e:
            logger.error(f"Error getting vulnerabilities data: {e}")
            return []
    
    def run(self, host="127.0.0.1", port=8080, debug=False):
        """Run the dashboard"""
        logger.info(f"Starting IoT Scanner Dashboard on {host}:{port}")
        self.app.run_server(host=host, port=port, debug=debug)

if __name__ == "__main__":
    dashboard = IoTScannerDashboard()
    dashboard.run(debug=True)
