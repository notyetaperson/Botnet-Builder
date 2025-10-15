# Advanced IoT Device Scanner & Exploitation Framework

A comprehensive, enterprise-grade IoT device scanning and exploitation framework designed for controlled environments. This advanced tool combines network discovery, vulnerability assessment, device fingerprinting, and exploitation capabilities in a single powerful platform.

## 🎨 GUI Features

The graphical user interface provides an intuitive, professional interface for all scanner functionality:

### **Main Features**
- **Real-Time Dashboard**: Live activity feed with color-coded status updates
- **Device Discovery Panel**: Tree view of all discovered devices with filtering
- **Vulnerability Viewer**: Categorized vulnerability display with severity levels
- **Console Output**: Full logging with syntax highlighting
- **Report Generation**: Visual report builder with multiple formats
- **Network Configuration**: Easy-to-use scan configuration panel
- **Statistics Cards**: Real-time scan metrics and progress tracking
- **Context Menus**: Right-click device actions and quick tools
- **Multi-Tab Interface**: Organized workflow with 5 main tabs

### **GUI Controls**
- Start/Stop/Pause scanning with one click
- Export results to multiple formats
- Filter and search devices and vulnerabilities
- Configure scan types (Quick, Full, Vulnerability, Stealth)
- Enable/disable fingerprinting, exploit testing, stealth mode
- Adjust thread count and performance settings

### **Visual Elements**
- Color-coded status indicators (Green=Secure, Red=Compromised, Orange=Vulnerable)
- Progress bars with percentage indicators
- Sortable and filterable data tables
- Syntax-highlighted console output
- Professional dark theme interface

## 🚀 Advanced Features

### **Multi-Protocol Network Discovery**
- **ARP Scanning**: Layer 2 discovery for local networks
- **ICMP Ping Sweep**: Traditional host discovery
- **TCP/UDP Port Scanning**: Comprehensive service detection
- **Service Discovery**: mDNS, SSDP, DHCP discovery
- **External Intelligence**: Shodan, Censys integration
- **Stealth Scanning**: Advanced evasion techniques

### **Advanced Device Fingerprinting**
- **HTTP/HTTPS Fingerprinting**: Web service analysis
- **SSL/TLS Analysis**: Certificate and cipher analysis
- **SNMP Fingerprinting**: Network device identification
- **UPnP Discovery**: IoT device enumeration
- **Banner Grabbing**: Service version detection
- **OS Detection**: Multi-technique OS identification
- **Device Classification**: AI-powered device type detection

### **Comprehensive Vulnerability Scanning**
- **CVE Database**: 1000+ known vulnerabilities
- **Web Application Testing**: SQL injection, XSS, directory traversal
- **Network Service Testing**: SSH, Telnet, SNMP, FTP vulnerabilities
- **IoT-Specific Testing**: MQTT, CoAP, UPnP, Modbus vulnerabilities
- **Exploit Verification**: Automated exploit testing
- **Custom Vulnerability Rules**: Extensible rule engine

### **Advanced Credential Testing**
- **Default Credentials**: 200+ vendor-specific combinations
- **Dictionary Attacks**: Custom wordlist support
- **Brute Force Protection**: Rate limiting and evasion
- **Multi-Protocol Support**: HTTP, SSH, Telnet, FTP, SNMP
- **Credential Intelligence**: Machine learning-based password generation

### **Enterprise Features**
- **Web Dashboard**: Real-time monitoring and control
- **Database Storage**: SQLite/PostgreSQL/MySQL support
- **REST API**: Programmatic access and integration
- **Plugin System**: Extensible architecture
- **Reporting Engine**: PDF, HTML, JSON, CSV output
- **Alerting System**: Email, Slack, webhook notifications
- **Performance Monitoring**: Prometheus/Grafana integration

## 📊 Supported Protocols & Services

### **Standard Services**
- SSH (22), Telnet (23), HTTP (80), HTTPS (443)
- FTP (21), SMTP (25), DNS (53), POP3 (110), IMAP (143)
- IMAPS (993), POP3S (995), SMTP-Submission (587)

### **IoT-Specific Services**
- MQTT (1883), MQTT-SSL (8883), CoAP (5683), CoAPS (5684)
- SNMP (161), SNMP-Trap (162), RTSP (554)
- UPnP (5000), SSDP (1900), Custom (9999)

### **Industrial Protocols**
- Modbus (502), S7 (102), EtherNet/IP (44818)
- BACnet (47808), DNP3 (20000), IEC-104 (2404)
- Profinet (9600)

### **Security Cameras**
- Dahua (37777), Hikvision (8000), Axis (M30)
- Foscam (FI), D-Link (DCS-), Netgear (Arlo)

### **Smart Home**
- Home Assistant (8080, 8123), Node-RED (3000, 1880)
- openHAB (Karaf), Domoticz (WebServer)

### **Database Services**
- MySQL (3306), PostgreSQL (5432), MSSQL (1433)
- Redis (6379), MongoDB (27017), CouchDB (5984)

### **Message Queues**
- RabbitMQ (5672), ActiveMQ (61616), Kafka (9092)

### **Monitoring**
- Grafana (3000), Prometheus (9090), Kibana (5601)

## 🛠️ Installation

### **🚀 One-Click Auto-Installation (Recommended)**

**Windows:**
```cmd
install.bat
```

**Linux/Mac:**
```bash
chmod +x install.sh
./install.sh
```

The auto-installer will:
- ✅ Check Python version compatibility
- ✅ Install tkinter (if needed)
- ✅ Download and install all requirements
- ✅ Test the installation
- ✅ Create launcher scripts
- ✅ Launch the GUI automatically

### **Manual Installation**

#### **Basic Installation**
```bash
pip install -r requirements.txt
```

#### **Advanced Installation (with all features)**
```bash
pip install -r advanced_requirements.txt
```

#### **GUI Only (minimal)**
```bash
pip install requests paramiko ipaddress
# GUI uses built-in tkinter - no additional packages needed
```

#### **Auto-Install Script**
```bash
python auto_install.py
```

### **Docker Installation**
```bash
docker build -t iot-scanner .
docker run -it --net=host iot-scanner
```

### **Note for Windows Users**
The GUI application requires Python's tkinter module which comes pre-installed with standard Python distributions. If you encounter issues, reinstall Python with tkinter enabled.

## 🚀 Usage

### **Command Line Interface**

#### **Quick Scan**
```bash
python iot_scanner.py --network 192.168.1.0/24 --scan-type quick
```

#### **Full Vulnerability Scan**
```bash
python iot_scanner.py --network 192.168.1.0/24 --scan-type full --enable-vuln-scan
```

#### **Stealth Scan**
```bash
python iot_scanner.py --network 192.168.1.0/24 --stealth-mode --max-threads 50
```

#### **Continuous Monitoring**
```bash
python iot_scanner.py --network 192.168.1.0/24 --continuous --interval 300
```

#### **Advanced Options**
```bash
python iot_scanner.py \
  --network 192.168.1.0/24 \
  --max-threads 200 \
  --enable-fingerprinting \
  --enable-vuln-scan \
  --enable-exploit-testing \
  --output-format json,csv,pdf \
  --database-type postgresql \
  --api-keys shodan:YOUR_KEY,censys:ID:SECRET
```

### **GUI Application (Recommended)**
```bash
python scanner_gui.py
```
Launch the full-featured graphical interface with real-time monitoring, device discovery, vulnerability scanning, and comprehensive reporting.

### **Web Dashboard**
```bash
python web_dashboard.py
```
Access at: http://localhost:8080

### **Configuration File**
```bash
python iot_scanner.py --config config.yaml
```

## 📋 Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--network` | Network range to scan | 192.168.1.0/24 |
| `--max-threads` | Maximum concurrent threads | 200 |
| `--scan-type` | Scan type (quick/full/vuln/stealth) | full |
| `--stealth-mode` | Enable stealth scanning | false |
| `--continuous` | Run continuous scanning | false |
| `--interval` | Scan interval in seconds | 300 |
| `--enable-fingerprinting` | Enable device fingerprinting | true |
| `--enable-vuln-scan` | Enable vulnerability scanning | true |
| `--enable-exploit-testing` | Enable exploit testing | false |
| `--output-format` | Output formats (json,csv,pdf,html) | json |
| `--database-type` | Database type (sqlite/postgresql/mysql) | sqlite |
| `--config` | Configuration file path | config.yaml |

## 🔧 Configuration

The tool uses YAML configuration files for advanced customization:

```yaml
# Network scanning configuration
network:
  default_range: "192.168.1.0/24"
  max_threads: 200
  stealth_mode: false

# Vulnerability scanning
vulnerabilities:
  enable_cve_scanning: true
  enable_web_vuln_scanning: true
  enable_iot_vuln_scanning: true

# External APIs
external_apis:
  shodan:
    enabled: true
    api_key: "YOUR_SHODAN_KEY"
  censys:
    enabled: true
    api_id: "YOUR_CENSYS_ID"
    api_secret: "YOUR_CENSYS_SECRET"
```

## 📊 Output Formats

### **JSON Output**
```json
{
  "scan_timestamp": "2024-01-01T12:00:00Z",
  "network_range": "192.168.1.0/24",
  "total_devices": 15,
  "compromised_devices": 3,
  "vulnerabilities_found": 8,
  "devices": [...],
  "vulnerabilities": [...],
  "statistics": {...}
}
```

### **CSV Output**
- Device inventory with IP, type, status, vulnerabilities
- Vulnerability details with CVE IDs and severity
- Credential findings with usernames and passwords

### **PDF Reports**
- Executive summary with key findings
- Technical details with screenshots
- Vulnerability assessment with remediation
- Network topology diagrams

## 🔒 Security Features

### **Stealth Scanning**
- Packet fragmentation
- Decoy IP addresses
- Source IP spoofing
- Random timing delays
- User agent randomization

### **Rate Limiting**
- Configurable request rates
- Adaptive timing based on responses
- Connection pooling
- Retry mechanisms

### **Evasion Techniques**
- Protocol-specific evasion
- IDS/IPS bypass methods
- Firewall traversal
- Network segmentation detection

## 🎯 Vulnerability Database

The tool includes a comprehensive vulnerability database covering:

- **Critical CVEs**: Log4Shell, Zerologon, BlueKeep, EternalBlue
- **IoT Vulnerabilities**: Default credentials, unencrypted protocols
- **Web Vulnerabilities**: SQL injection, XSS, directory traversal
- **Network Vulnerabilities**: Weak ciphers, outdated services
- **Industrial Vulnerabilities**: Modbus, DNP3, S7 protocol issues

## 🔌 Plugin System

Extend functionality with custom plugins:

```python
class CustomPlugin:
    def __init__(self):
        self.name = "Custom Scanner"
    
    def scan(self, target):
        # Custom scanning logic
        return results
    
    def exploit(self, target, vulnerability):
        # Custom exploitation logic
        return success
```

## 📈 Performance

- **High-Speed Scanning**: 200+ concurrent threads
- **Memory Efficient**: Optimized data structures
- **Scalable**: Supports large network ranges
- **Real-Time**: Live dashboard updates
- **Distributed**: Multi-node scanning support

## 🚨 Alerting & Monitoring

### **Real-Time Alerts**
- Email notifications for critical findings
- Slack integration for team notifications
- Webhook support for custom integrations
- SMS alerts for emergency situations

### **Monitoring Integration**
- Prometheus metrics export
- Grafana dashboard templates
- Elasticsearch log shipping
- Kibana visualization support

## 🔍 Advanced Analytics

### **Machine Learning**
- Device type classification
- Anomaly detection
- Threat prediction
- Behavioral analysis

### **Threat Intelligence**
- Shodan integration
- Censys data correlation
- VirusTotal scanning
- Geolocation analysis

## 📚 API Documentation

### **REST API Endpoints**
```
GET /api/v1/devices - List discovered devices
GET /api/v1/vulnerabilities - List vulnerabilities
POST /api/v1/scan - Start new scan
GET /api/v1/scan/{id}/status - Get scan status
GET /api/v1/reports/{id} - Download report
```

### **WebSocket Events**
```
scan.progress - Real-time scan progress
device.discovered - New device found
vulnerability.found - Vulnerability detected
exploit.success - Successful exploitation
```

## 🛡️ Security Notice

**⚠️ IMPORTANT**: This tool is designed exclusively for use in controlled, isolated environments with proper authorization. Users must:

- Obtain explicit written permission before scanning any network
- Use only in authorized penetration testing scenarios
- Comply with all applicable laws and regulations
- Implement proper access controls and monitoring
- Maintain audit logs of all scanning activities

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests for any improvements.

## 📞 Support

For support, feature requests, or security issues, please contact the development team or create an issue in the repository.

---

**Remember**: With great power comes great responsibility. Use this tool ethically and legally.

## 🖥️ Interface Options

This framework offers three ways to interact with the scanner:

1. **GUI Application (scanner_gui.py)** - Recommended for most users
   - Professional graphical interface
   - Real-time monitoring and visualization
   - Easy configuration and control
   - Multi-tab organization
   - Built-in reporting

2. **Web Dashboard (web_dashboard.py)** - For remote access
   - Browser-based interface
   - Dash/Plotly visualizations
   - REST API integration
   - Multi-user capable

3. **Command Line (iot_scanner.py)** - For automation
   - Scriptable interface
   - Perfect for CI/CD integration
   - Cron job compatible
   - Maximum flexibility

### Quick Launch

**🚀 One-Click Install & Launch:**
```bash
# Windows
install.bat

# Linux/Mac
chmod +x install.sh
./install.sh
```

**📱 Launch GUI (after installation):**
```bash
# Windows
launch_gui.bat

# Linux/Mac
chmod +x launch_gui.sh
./launch_gui.sh

# Or directly
python scanner_gui.py
```

**🔧 Auto-Install Requirements Only:**
```bash
python auto_install.py
```
