

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import scapy.all as scapy
from scapy.layers import http, dns, tls
import base64
import binascii
import re
import math
import string
from datetime import datetime
import json
import threading
import os
import zlib
import pandas as pd
import struct
from queue import Queue
import time
import socket
from typing import Dict, List, Tuple, Any

class LivePacketScanner:
    def __init__(self, packet_callback, interface=None):
        self.packet_callback = packet_callback
        self.interface = interface
        self.is_running = False
        self.capture_thread = None
        self.packet_queue = Queue()

    def start_capture(self):
        if self.is_running:
            return
        
        self.is_running = True
        self.capture_thread = threading.Thread(target=self._capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def stop_capture(self):
        self.is_running = False
        if self.capture_thread:
            self.capture_thread.join()

    def _capture_packets(self):
        def packet_handler(packet):
            if self.is_running:
                self.packet_queue.put(packet)
                self.packet_callback(packet)

        try:
            scapy.sniff(
                iface=self.interface,
                prn=packet_handler,
                store=False,
                stop_filter=lambda _: not self.is_running
            )
        except Exception as e:
            print(f"Capture error: {e}")

    def get_available_interfaces(self):
        try:
            # Get the network interfaces with their descriptions
            interfaces = {}
            if os.name == "nt":  # Windows
                from scapy.arch.windows import get_windows_if_list
                for iface in get_windows_if_list():
                    # Use name or description as the display name
                    display_name = iface.get('description', iface.get('name', ''))
                    if display_name:
                        interfaces[iface['name']] = display_name
            else:  # Linux/Unix/MacOS
                for iface in scapy.get_if_list():
                    # On Unix-like systems, the interface name is usually descriptive enough
                    interfaces[iface] = iface

            return interfaces
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            return {}

class ProtocolDecoder:
    def __init__(self):
        # Register known application layer protocols
        self.app_protocols = {
            80: 'HTTP',
            443: 'HTTPS',
            53: 'DNS',
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            110: 'POP3',
            143: 'IMAP',
            445: 'SMB',
            3306: 'MySQL',
            1433: 'MSSQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB'
        }

    def decode_packet(self, packet):
        """Main packet decoding method"""
        decoded_info = {
            'timestamp': self.get_timestamp(packet),
            'layer2': self.decode_layer2(packet),
            'layer3': self.decode_layer3(packet),
            'layer4': self.decode_layer4(packet),
            'layer7': self.decode_layer7(packet),
            'payload': self.decode_payload(packet),
            'protocols': self.identify_protocols(packet),
            'raw_data': self.get_raw_data(packet)
        }
        return decoded_info

    def get_timestamp(self, packet):
        """Extract and format packet timestamp"""
        return {
            'epoch': packet.time,
            'formatted': datetime.fromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S.%f')
        }

    def decode_layer2(self, packet):
        """Decode Layer 2 (Data Link Layer) information"""
        l2_info = {}
        
        if packet.haslayer('Ether'):
            l2_info['type'] = 'Ethernet'
            l2_info['src_mac'] = packet.src
            l2_info['dst_mac'] = packet.dst
            l2_info['ethertype'] = hex(packet.type)
            
        elif packet.haslayer('Dot11'):
            l2_info['type'] = 'WiFi'
            l2_info['src_mac'] = packet.addr2
            l2_info['dst_mac'] = packet.addr1
            l2_info['bssid'] = packet.addr3
            
        return l2_info

    def decode_layer3(self, packet):
        """Decode Layer 3 (Network Layer) information"""
        l3_info = {}
        
        if packet.haslayer('IP'):
            l3_info['type'] = 'IPv4'
            l3_info['src_ip'] = packet[scapy.IP].src
            l3_info['dst_ip'] = packet[scapy.IP].dst
            l3_info['ttl'] = packet[scapy.IP].ttl
            l3_info['id'] = packet[scapy.IP].id
            l3_info['flags'] = self.decode_ip_flags(packet[scapy.IP].flags)
            l3_info['tos'] = packet[scapy.IP].tos
            l3_info['length'] = packet[scapy.IP].len
            
        elif packet.haslayer('IPv6'):
            l3_info['type'] = 'IPv6'
            l3_info['src_ip'] = packet[scapy.IPv6].src
            l3_info['dst_ip'] = packet[scapy.IPv6].dst
            l3_info['traffic_class'] = packet[scapy.IPv6].tc
            l3_info['flow_label'] = packet[scapy.IPv6].fl
            l3_info['hop_limit'] = packet[scapy.IPv6].hlim
            
        elif packet.haslayer('ARP'):
            l3_info['type'] = 'ARP'
            l3_info['op'] = 'Request' if packet[scapy.ARP].op == 1 else 'Reply'
            l3_info['src_ip'] = packet[scapy.ARP].psrc
            l3_info['dst_ip'] = packet[scapy.ARP].pdst
            l3_info['src_mac'] = packet[scapy.ARP].hwsrc
            l3_info['dst_mac'] = packet[scapy.ARP].hwdst
            
        return l3_info

    def decode_layer4(self, packet):
        """Decode Layer 4 (Transport Layer) information"""
        l4_info = {}
        
        if packet.haslayer('TCP'):
            l4_info['type'] = 'TCP'
            l4_info['src_port'] = packet[scapy.TCP].sport
            l4_info['dst_port'] = packet[scapy.TCP].dport
            l4_info['seq'] = packet[scapy.TCP].seq
            l4_info['ack'] = packet[scapy.TCP].ack
            l4_info['flags'] = self.decode_tcp_flags(packet[scapy.TCP].flags)
            l4_info['window'] = packet[scapy.TCP].window
            l4_info['urgent_ptr'] = packet[scapy.TCP].urgptr
            l4_info['options'] = self.decode_tcp_options(packet[scapy.TCP].options)
            
        elif packet.haslayer('UDP'):
            l4_info['type'] = 'UDP'
            l4_info['src_port'] = packet[scapy.UDP].sport
            l4_info['dst_port'] = packet[scapy.UDP].dport
            l4_info['length'] = packet[scapy.UDP].len
            
        elif packet.haslayer('ICMP'):
            l4_info['type'] = 'ICMP'
            l4_info['type_id'] = packet[scapy.ICMP].type
            l4_info['code'] = packet[scapy.ICMP].code
            l4_info['type_name'] = self.get_icmp_type_name(packet[scapy.ICMP].type)
            
        return l4_info

    def decode_layer7(self, packet):
        """Decode Layer 7 (Application Layer) protocols"""
        l7_info = {}
        
        # HTTP Detection and Decoding
        if packet.haslayer('HTTP'):
            l7_info['protocol'] = 'HTTP'
            l7_info['http'] = self.decode_http(packet)
            
        # DNS Detection and Decoding
        elif packet.haslayer('DNS'):
            l7_info['protocol'] = 'DNS'
            l7_info['dns'] = self.decode_dns(packet)
            
        # TLS/SSL Detection
        elif packet.haslayer('TLS'):
            l7_info['protocol'] = 'TLS'
            l7_info['tls'] = self.decode_tls(packet)
            
        # Detect other protocols based on ports
        elif packet.haslayer('TCP') or packet.haslayer('UDP'):
            port = min(packet[scapy.TCP].sport if packet.haslayer('TCP') else packet[scapy.UDP].sport,
                      packet[scapy.TCP].dport if packet.haslayer('TCP') else packet[scapy.UDP].dport)
            if port in self.app_protocols:
                l7_info['protocol'] = self.app_protocols[port]
                l7_info['port'] = port
                
        return l7_info

    def decode_http(self, packet):
        """Decode HTTP protocol details"""
        http_info = {}
        
        if packet.haslayer('HTTP'):
            # HTTP Request
            if packet.haslayer('HTTPRequest'):
                http_info['type'] = 'Request'
                http_info['method'] = packet[http.HTTPRequest].Method.decode()
                http_info['path'] = packet[http.HTTPRequest].Path.decode()
                http_info['version'] = packet[http.HTTPRequest].Http_Version.decode()
                http_info['headers'] = self.decode_http_headers(packet[http.HTTPRequest].fields)
                
            # HTTP Response
            elif packet.haslayer('HTTPResponse'):
                http_info['type'] = 'Response'
                http_info['status_code'] = packet[http.HTTPResponse].Status_Code
                http_info['reason'] = packet[http.HTTPResponse].Reason_Phrase.decode()
                http_info['version'] = packet[http.HTTPResponse].Http_Version.decode()
                http_info['headers'] = self.decode_http_headers(packet[http.HTTPResponse].fields)
                
        return http_info

    def decode_dns(self, packet):
        """Decode DNS protocol details"""
        dns_info = {}
        
        if packet.haslayer('DNS'):
            dns = packet['DNS']
            dns_info['id'] = dns.id
            dns_info['qr'] = 'Response' if dns.qr else 'Query'
            dns_info['opcode'] = dns.opcode
            dns_info['rcode'] = dns.rcode
            
            # Queries
            if dns.qd:
                dns_info['queries'] = [{
                    'name': query.qname.decode(),
                    'type': self.get_dns_type(query.qtype)
                } for query in dns.qd]
                
            # Answers
            if dns.an:
                dns_info['answers'] = [{
                    'name': rr.rrname.decode(),
                    'type': self.get_dns_type(rr.type),
                    'data': self.get_dns_rdata(rr)
                } for rr in dns.an]
                
        return dns_info

    def decode_tls(self, packet):
        """Decode TLS protocol details"""
        tls_info = {}
        
        if packet.haslayer('TLS'):
            tls = packet['TLS']
            tls_info['type'] = self.get_tls_type(tls.type)
            tls_info['version'] = self.get_tls_version(tls.version)
            
            # Handle different TLS message types
            if tls.haslayer('TLSClientHello'):
                tls_info['message_type'] = 'Client Hello'
                tls_info['cipher_suites'] = self.decode_cipher_suites(tls['TLSClientHello'].cipher_suites)
                
            elif tls.haslayer('TLSServerHello'):
                tls_info['message_type'] = 'Server Hello'
                tls_info['cipher_suite'] = self.get_cipher_suite_name(tls['TLSServerHello'].cipher_suite)
                
        return tls_info

    def decode_payload(self, packet):
        """Decode packet payload with multiple encoding attempts"""
        payload_info = {}
        
        if packet.haslayer('TCP'):
            payload = bytes(packet[scapy.TCP].payload)
        elif packet.haslayer('UDP'):
            payload = bytes(packet[scapy.UDP].payload)
        else:
            payload = bytes(packet.payload)
            
        if payload:
            payload_info['raw'] = {
                'hex': payload.hex(),
                'length': len(payload)
            }
            
            # Try various decodings
            try:
                payload_info['utf8'] = payload.decode('utf-8', errors='ignore')
            except:
                pass
                
            try:
                payload_info['ascii'] = payload.decode('ascii', errors='ignore')
            except:
                pass
                
            # Try base64 decoding
            try:
                decoded = base64.b64decode(payload + b'=' * (-len(payload) % 4))
                payload_info['base64'] = {
                    'decoded_hex': decoded.hex(),
                    'decoded_utf8': decoded.decode('utf-8', errors='ignore')
                }
            except:
                pass
                
            # Try JSON decoding
            try:
                json_data = json.loads(payload)
                payload_info['json'] = json_data
            except:
                pass
                
        return payload_info

    def identify_protocols(self, packet):
        """Identify all protocols in the packet"""
        protocols = []
        
        # Layer 2
        if packet.haslayer('Ether'):
            protocols.append('Ethernet')
        elif packet.haslayer('Dot11'):
            protocols.append('802.11')
            
        # Layer 3
        if packet.haslayer('IP'):
            protocols.append('IPv4')
        elif packet.haslayer('IPv6'):
            protocols.append('IPv6')
        elif packet.haslayer('ARP'):
            protocols.append('ARP')
            
        # Layer 4
        if packet.haslayer('TCP'):
            protocols.append('TCP')
        elif packet.haslayer('UDP'):
            protocols.append('UDP')
        elif packet.haslayer('ICMP'):
            protocols.append('ICMP')
            
        # Application Layer
        if packet.haslayer('HTTP'):
            protocols.append('HTTP')
        elif packet.haslayer('DNS'):
            protocols.append('DNS')
        elif packet.haslayer('TLS'):
            protocols.append('TLS')
            
        return protocols

    # Helper methods
    def get_raw_data(self, packet):
        """Get raw packet data"""
        return {
            'raw_hex': bytes(packet).hex(),
            'length': len(packet),
            'summary': packet.summary()
        }

    def decode_tcp_flags(self, flags):
        """Decode TCP flags"""
        flag_map = {
            'F': 'FIN',
            'S': 'SYN',
            'R': 'RST',
            'P': 'PSH',
            'A': 'ACK',
            'U': 'URG',
            'E': 'ECE',
            'C': 'CWR'
        }
        return [flag_map[f] for f in str(flags)]

    def decode_ip_flags(self, flags):
        """Decode IP flags"""
        flag_map = {
            'DF': 'Don\'t Fragment',
            'MF': 'More Fragments'
        }
        return [flag_map[f] for f in str(flags).split('+') if f in flag_map]

    def get_icmp_type_name(self, type_id):
        """Get ICMP type name"""
        icmp_types = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            5: 'Redirect',
            8: 'Echo Request',
            11: 'Time Exceeded'
        }
        return icmp_types.get(type_id, f'Unknown ({type_id})')

    def decode_http_headers(self, fields):
        """Decode HTTP headers"""
        headers = {}
        for field in fields:
            if field.startswith('Http_'):
                header_name = field.replace('Http_', '').replace('_', '-')
                headers[header_name] = fields[field]
        return headers

    def get_tls_version(self, version):
        """Get TLS version name"""
        versions = {
            0x0300: 'SSL 3.0',
            0x0301: 'TLS 1.0',
            0x0302: 'TLS 1.1',
            0x0303: 'TLS 1.2',
            0x0304: 'TLS 1.3'
        }
        return versions.get(version, f'Unknown (0x{version:04x})')

    def get_tls_type(self, type_id):
        """Get TLS content type name"""
        types = {
            20: 'Change Cipher Spec',
            21: 'Alert',
            22: 'Handshake',
            23: 'Application Data'
        }
        return types.get(type_id, f'Unknown ({type_id})')

    def decode_tcp_options(self, options):
        """Decode TCP options"""
        decoded_options = {}
        for option in options:
            if len(option) == 2:
                decoded_options[option[0]] = option[1]
            else:
                decoded_options[option[0]] = None
        return decoded_options

    def get_dns_type(self, qtype):
        """Get DNS query type name"""
        dns_types = {
            1: 'A',
            2: 'NS',
            5: 'CNAME',
            6: 'SOA',
            12: 'PTR',
            15: 'MX',
            16: 'TXT',
            28: 'AAAA'
        }
        return dns_types.get(qtype, f'Unknown ({qtype})')

    def get_dns_rdata(self, rr):  
       """Get formatted DNS record data"""  
       if rr.type == 1:  # A record  
          return rr.rdata if hasattr(rr, 'rdata') else None  
       elif rr.type == 28:  # AAAA record  
          return rr.rdata if hasattr(rr, 'rdata') else None  
       elif rr.type == 5:  # CNAME record  
          return rr.rdata.decode() if hasattr(rr, 'rdata') else None  
       elif rr.type == 15:  # MX record  
          return f"{rr.preference} {rr.exchange.decode()}" if hasattr(rr, 'exchange') else None  
       return str(rr) if hasattr(rr, '__str__') else "Unknown"


class EncodingDetector:
    def __init__(self):
        self.patterns = {
            'base64': re.compile(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'),
            'hex': re.compile(r'^[0-9a-fA-F]+$'),
            'binary': re.compile(r'^[01]+$'),
            'jwt': re.compile(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'),
            'uuid': re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
            'ip': re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'),
            'zlib': re.compile(rb'^\x78[\x01\x9c\xda\x5e]')
        }
        try:
            import zlib as zlib_module
            self.zlib = zlib_module
            self.zlib_available = True
        except ImportError:
            self.zlib_available = False
            print("Warning: zlib module not available")

    def calculate_entropy(self, data):
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = data.count(bytes([x])) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy

    def detect_encoding(self, data):
        results = []
        try:
            str_data = data.decode('utf-8', errors='ignore')
        except:
            str_data = ""

        entropy = self.calculate_entropy(data)

        # Check for zlib compression first
        if self.zlib_available:
            try:
                if len(data) >= 2 and data.startswith(b'\x78'):
                    decompressed = self.zlib.decompress(data)
                    results.append(('Zlib', decompressed, 0.95))
                    try:
                        decoded_str = decompressed.decode('utf-8', errors='ignore')
                        if self.is_printable(decompressed):
                            results.append(('Zlib->Text', decoded_str, 0.90))
                    except:
                        pass
            except:
                pass

        # Base64 detection
        if self.patterns['base64'].match(str_data):
            try:
                decoded = base64.b64decode(data + b'=' * (-len(data) % 4))
                if self.is_printable(decoded):
                    results.append(('Base64', decoded, 0.9))

                # Check if base64 decoded data is zlib compressed
                if self.zlib_available:
                    try:
                        if decoded.startswith(b'\x78'):
                            decompressed = self.zlib.decompress(decoded)
                            results.append(('Base64->Zlib', decompressed, 0.85))
                    except:
                        pass
            except:
                pass

        # Hex detection
        if self.patterns['hex'].match(str_data):
            try:
                decoded = bytes.fromhex(str_data)
                if self.is_printable(decoded):
                    results.append(('Hex', decoded, 0.8))

                # Check if hex decoded data is zlib compressed
                if self.zlib_available:
                    try:
                        if decoded.startswith(b'\x78'):
                            decompressed = self.zlib.decompress(decoded)
                            results.append(('Hex->Zlib', decompressed, 0.75))
                    except:
                        pass
            except:
                pass

        # JWT detection
        if self.patterns['jwt'].match(str_data):
            results.append(('JWT', None, 0.95))

        # Compressed/Encrypted detection
        if entropy > 7.5:
            results.append(('Compressed', None, 0.7))
        if 7.8 <= entropy <= 8.0:
            results.append(('Encrypted', None, 0.8))

        return results if results else []

    def is_printable(self, data):
        try:
            text = data.decode('utf-8')
            return all(char in string.printable for char in text)
        except:
            return False

class PacketDecoder:
    def __init__(self):
        self.protocol_decoder = ProtocolDecoder()
        self.encoding_detector = EncodingDetector()

    def decode_packet(self, packet):
        """Complete packet decoding and analysis"""
        # Get basic protocol decoding
        decoded = self.protocol_decoder.decode_packet(packet)
        
        # Add payload analysis
        if packet.haslayer('Raw'):
            payload = bytes(packet[scapy.Raw].load)
            decoded['payload_analysis'] = self.analyze_payload(payload)

        return decoded

    def analyze_payload(self, payload):
        """Comprehensive payload analysis"""
        analysis = {
            'length': len(payload),
            'hex': payload.hex(),
            'entropy': self.encoding_detector.calculate_entropy(payload)
        }
        
        # Try to decode as text
        try:
            analysis['utf8'] = payload.decode('utf-8')
        except:
            try:
                analysis['ascii'] = payload.decode('ascii', errors='replace')
            except:
                pass

        # Detect encodings
        encodings = self.encoding_detector.detect_encoding(payload)
        if encodings:
            analysis['detected_encodings'] = []
            for encoding, decoded, confidence in encodings:
                encoding_info = {
                    'type': encoding,
                    'confidence': confidence
                }
                if decoded:
                    try:
                        if isinstance(decoded, bytes):
                            encoding_info['decoded'] = {
                                'hex': decoded.hex(),
                                'utf8': decoded.decode('utf-8', errors='ignore')
                            }
                        else:
                            encoding_info['decoded'] = str(decoded)
                    except:
                        encoding_info['decoded'] = {
                            'hex': decoded.hex() if isinstance(decoded, bytes) else None
                        }
                analysis['detected_encodings'].append(encoding_info)

        # Try to identify file signatures
        file_type = self.identify_file_signature(payload)
        if file_type:
            analysis['file_type'] = file_type

        return analysis

    def identify_file_signature(self, data):
        """Identify file type based on magic numbers"""
        signatures = {
            b'\xFF\xD8\xFF': 'JPEG',
            b'\x89PNG\r\n\x1A\n': 'PNG',
            b'GIF87a': 'GIF',
            b'GIF89a': 'GIF',
            b'%PDF': 'PDF',
            b'PK\x03\x04': 'ZIP',
            b'PK\x05\x06': 'ZIP',
            b'PK\x07\x08': 'ZIP',
            b'\x1F\x8B\x08': 'GZIP',
            b'\x42\x5A\x68': 'BZIP2',
            b'\x75\x73\x74\x61\x72': 'TAR',
            b'\x52\x61\x72\x21\x1A\x07': 'RAR',
            b'\x7F\x45\x4C\x46': 'ELF',
            b'\x4D\x5A': 'EXE',
            b'\x25\x21\x50\x53': 'PS'
        }
        
        for signature, filetype in signatures.items():
            if data.startswith(signature):
                return filetype
        return None

class CoordinateAnalyzer:
    def __init__(self):
        self.formats = {
            'float32': '<fff',  # Little-endian, 3 floats
            'float64': '<ddd',  # Little-endian, 3 doubles
            'int32': '<iii'     # Little-endian, 3 integers
        }
        self.csv_data = None

    def load_csv(self, filename):
        try:
            self.csv_data = pd.read_csv(filename)
            return True
        except Exception as e:
            raise Exception(f"Failed to load CSV: {str(e)}")

    def find_coordinates(self, payload, timestamp):
        results = []
        for format_name, format_str in self.formats.items():
            size = struct.calcsize(format_str)
            for i in range(0, len(payload) - size + 1):
                try:
                    x, y, z = struct.unpack(format_str, payload[i:i+size])
                    if self.is_valid_coordinate(x, y, z):
                        results.append({
                            'offset': i,
                            'format': format_name,
                            'x': x, 'y': y, 'z': z,
                            'timestamp': timestamp
                        })
                except:
                    continue
        return results

    def is_valid_coordinate(self, x, y, z):
        return all([
            isinstance(x, (int, float)),
            isinstance(y, (int, float)),
            isinstance(z, (int, float)),
            abs(x) < 1e6,
            abs(y) < 1e6,
            abs(z) < 1e6
        ])

class PacketAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Network Packet Analyzer")
        self.root.geometry("1200x800")

        # Initialize analyzers
        self.detector = EncodingDetector()
        self.packet_decoder = PacketDecoder()
        self.coordinate_analyzer = CoordinateAnalyzer()
        self.payload_decoder = PayloadDecoder()
        
        # Initialize packet storage
        self.packets = []
        self.original_packets = []
        self.current_packet_index = 0
        
        # Initialize live scanner
        self.scanner = LivePacketScanner(self.process_live_packet)
        self.is_scanning = False

        # Create GUI components
        self.create_gui()
        self.add_protocol_filters()
        self.add_export_options()
        self.setup_live_capture_controls()
        self.setup_protocol_analysis_frame()

    def setup_live_capture_controls(self):
        """Add live capture controls to the GUI"""
        capture_frame = ttk.LabelFrame(self.root, text="Live Capture")
        capture_frame.pack(fill='x', padx=15, pady=2)

        # Interface selection
        self.interface_var = tk.StringVar()
        self.interface_map = self.scanner.get_available_interfaces()
        
        # Create a reverse mapping for looking up interface names
        self.interface_name_to_guid = {v: k for k, v in self.interface_map.items()}
        
        interface_names = list(self.interface_map.values())
        if interface_names:
            self.interface_var.set(interface_names[0])
        
        ttk.Label(capture_frame, text="Interface:").pack(side='left', padx=2)
        interface_menu = ttk.Combobox(capture_frame, textvariable=self.interface_var, values=interface_names)
        interface_menu.pack(side='left', padx=2)

        # Start/Stop capture button
        self.capture_button = ttk.Button(capture_frame, text="Start Capture", command=self.toggle_capture)
        self.capture_button.pack(side='left', padx=2)

        # Packet count label
        self.packet_count_var = tk.StringVar(value="Packets: 0")
        ttk.Label(capture_frame, textvariable=self.packet_count_var).pack(side='left', padx=2)

    def setup_protocol_analysis_frame(self):
        """Setup the protocol analysis frame with tabs"""
        protocol_frame = ttk.LabelFrame(self.root, text="Protocol Analysis")
        protocol_frame.pack(fill='x', padx=15, pady=2)

        # Create notebook for protocol tabs
        self.protocol_notebook = ttk.Notebook(protocol_frame)
        self.protocol_notebook.pack(fill='both', expand=True, padx=5, pady=5)

        # Create protocol overview tab
        protocol_tab = ttk.Frame(self.protocol_notebook)
        self.protocol_text = scrolledtext.ScrolledText(protocol_tab, height=8)
        self.protocol_text.pack(fill='both', expand=True)
        self.protocol_notebook.add(protocol_tab, text='Protocol Overview')

        # Create HTTP tab
        http_tab = ttk.Frame(self.protocol_notebook)
        self.http_text = scrolledtext.ScrolledText(http_tab, height=8)
        self.http_text.pack(fill='both', expand=True)
        self.protocol_notebook.add(http_tab, text='HTTP')

        # Create DNS tab
        dns_tab = ttk.Frame(self.protocol_notebook)
        self.dns_text = scrolledtext.ScrolledText(dns_tab, height=8)
        self.dns_text.pack(fill='both', expand=True)
        self.protocol_notebook.add(dns_tab, text='DNS')

        # Create TLS tab
        tls_tab = ttk.Frame(self.protocol_notebook)
        self.tls_text = scrolledtext.ScrolledText(tls_tab, height=8)
        self.tls_text.pack(fill='both', expand=True)
        self.protocol_notebook.add(tls_tab, text='TLS/SSL')

    def setup_location_tracking_frame(self):
        """Setup the location tracking frame"""
        location_frame = ttk.LabelFrame(self.root, text="Location Tracking")
        location_frame.pack(fill='x', padx=15, pady=2)

        # Location tracking controls
        control_frame = ttk.Frame(location_frame)
        control_frame.pack(fill='x', padx=5, pady=2)

        # Start/Stop logging button
        self.log_button = ttk.Button(control_frame, text="Start Location Logging", 
                                   command=self.toggle_location_logging)
        self.log_button.pack(side='left', padx=2)

        # Current location display
        self.location_var = tk.StringVar(value="Location: Not detected")
        ttk.Label(control_frame, textvariable=self.location_var).pack(side='left', padx=10)

        # Location history
        self.location_text = scrolledtext.ScrolledText(location_frame, height=6)
        self.location_text.pack(fill='x', padx=5, pady=5)

    def toggle_location_logging(self):
        """Toggle location logging on/off"""
        if not hasattr(self, 'logging_active') or not self.logging_active:
            self.logging_active = True
            self.log_button.configure(text="Stop Location Logging")
            self.location_tracker.start_logging()
            self.status_var.set("Location logging started")
        else:
            self.logging_active = False
            self.log_button.configure(text="Start Location Logging")
            self.location_tracker.stop_logging()
            self.status_var.set("Location logging stopped")

    def update_location_display(self, location):
        """Update location display with new coordinates"""
        if location:
            self.location_var.set(
                f"Location: X: {location['x']:.2f}, Y: {location['y']:.2f}, Z: {location['z']:.2f}"
            )
            
            # Update history display
            self.location_text.delete(1.0, tk.END)
            history = self.location_tracker.get_location_history()
            for loc in history:
                timestamp = datetime.fromtimestamp(loc['timestamp']).strftime('%H:%M:%S.%f')[:-3]
                self.location_text.insert(tk.END, 
                    f"[{timestamp}] X: {loc['x']:.2f}, Y: {loc['y']:.2f}, Z: {loc['z']:.2f}\n"
                )

    def create_gui(self):
        """Create the main GUI components"""
        # Create main container
        main_container = ttk.Frame(self.root)
        main_container.pack(fill='both', expand=True, padx=10, pady=5)

        # Top menu
        top_menu = tk.Menu(self.root)
        self.root.config(menu=top_menu)

        file_menu = tk.Menu(top_menu, tearoff=0)
        top_menu.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open PCAP", command=self.open_pcap)
        file_menu.add_command(label="Save Analysis", command=self.save_analysis)
        file_menu.add_command(label="Export to JSON", command=self.export_to_json)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        # Toolbar
        toolbar = tk.Frame(main_container)
        toolbar.pack(fill='x', padx=5, pady=5)

        tk.Button(toolbar, text="Open", command=self.open_pcap).pack(side='left', padx=2)
        tk.Button(toolbar, text="Save", command=self.save_analysis).pack(side='left', padx=2)
        tk.Button(toolbar, text="Export", command=self.export_to_json).pack(side='left', padx=2)
        tk.Button(toolbar, text="Filter", command=self.apply_filter).pack(side='left', padx=2)
        tk.Button(toolbar, text="Reset", command=self.reset_filters).pack(side='left', padx=2)
        tk.Button(toolbar, text="Load CSV", command=self.load_coordinate_csv).pack(side='left', padx=2)
        tk.Button(toolbar, text="Find Coordinates", command=self.analyze_coordinates).pack(side='left', padx=2)

        # Create main content area with PanedWindow
        paned_window = ttk.PanedWindow(main_container, orient='horizontal')
        paned_window.pack(fill='both', expand=True, pady=5)

        # Left panel - Packet List
        left_frame = ttk.Frame(paned_window)
        self.packet_tree = ttk.Treeview(left_frame, columns=('No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length'))
        self.packet_tree.heading('No.', text='No.')
        self.packet_tree.heading('Time', text='Time')
        self.packet_tree.heading('Source', text='Source')
        self.packet_tree.heading('Destination', text='Destination')
        self.packet_tree.heading('Protocol', text='Protocol')
        self.packet_tree.heading('Length', text='Length')

        self.packet_tree.column('No.', width=50)
        self.packet_tree.column('Time', width=100)
        self.packet_tree.column('Source', width=120)
        self.packet_tree.column('Destination', width=120)
        self.packet_tree.column('Protocol', width=70)
        self.packet_tree.column('Length', width=60)

        scrollbar = ttk.Scrollbar(left_frame, orient='vertical', command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=scrollbar.set)

        self.packet_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        paned_window.add(left_frame, weight=1)

        # Right panel with notebook
        right_frame = ttk.Frame(paned_window)
        self.right_notebook = ttk.Notebook(right_frame)
        self.right_notebook.pack(fill='both', expand=True)

        # Details tab
        details_frame = ttk.Frame(self.right_notebook)
        self.details_text = scrolledtext.ScrolledText(details_frame, height=10)
        self.details_text.pack(fill='both', expand=True, padx=5, pady=5)
        self.right_notebook.add(details_frame, text='Packet Details')

        # Payload tab
        payload_frame = ttk.Frame(self.right_notebook)
        self.payload_text = scrolledtext.ScrolledText(payload_frame, height=10)
        self.payload_text.pack(fill='both', expand=True, padx=5, pady=5)
        self.right_notebook.add(payload_frame, text='Payload Analysis')

        paned_window.add(right_frame, weight=2)

        # Status bar
        self.status_var = tk.StringVar()
        status_bar = ttk.Label(main_container, textvariable=self.status_var, relief='sunken', anchor='w')
        status_bar.pack(fill='x', pady=2)

        # Filter variable
        self.filter_var = tk.StringVar()

        # Bind events
        self.packet_tree.bind('<<TreeviewSelect>>', self.on_packet_select)

    def add_protocol_filters(self):
        """Add quick filter buttons for common protocols"""
        filter_frame = ttk.LabelFrame(self.root, text="Quick Filters")
        filter_frame.pack(fill='x', padx=15, pady=2)

        ttk.Button(filter_frame, text="TCP Only",
                  command=lambda: self.apply_quick_filter("TCP")).pack(side='left', padx=2)
        ttk.Button(filter_frame, text="UDP Only",
                  command=lambda: self.apply_quick_filter("UDP")).pack(side='left', padx=2)
        ttk.Button(filter_frame, text="HTTP",
                  command=lambda: self.apply_quick_filter("HTTP")).pack(side='left', padx=2)
        ttk.Button(filter_frame, text="DNS",
                  command=lambda: self.apply_quick_filter("DNS")).pack(side='left', padx=2)
        ttk.Button(filter_frame, text="Reset Filters",
                  command=self.reset_filters).pack(side='left', padx=2)

    def add_export_options(self):
        """Add export menu options"""
        export_menu = tk.Menu(self.root)
        self.root.config(menu=export_menu)

        file_menu = tk.Menu(export_menu, tearoff=0)
        export_menu.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open PCAP", command=self.open_pcap)
        file_menu.add_command(label="Save Analysis", command=self.save_analysis)
        file_menu.add_command(label="Export to JSON", command=self.export_to_json)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

    def toggle_capture(self):
        """Toggle live packet capture on/off"""
        if not self.is_scanning:
            selected_name = self.interface_var.get()
            # Get the actual interface identifier from our mapping
            if selected_name in self.interface_name_to_guid:
                self.scanner.interface = self.interface_name_to_guid[selected_name]
                self.scanner.start_capture()
                self.is_scanning = True
                self.capture_button.configure(text="Stop Capture")
                self.status_var.set(f"Live capture started on {selected_name}...")
            else:
                messagebox.showerror("Error", "Please select a valid network interface")
                return
        else:
            self.scanner.stop_capture()
            self.is_scanning = False
            self.capture_button.configure(text="Start Capture")
            self.status_var.set("Live capture stopped")

    def process_live_packet(self, packet):
        """Process each captured packet"""
        self.packets.append(packet)
        self.original_packets.append(packet)
        
        # Decode packet
        decoded_packet = self.packet_decoder.decode_packet(packet)
        
        # Check for location data
        if 'payload' in decoded_packet and decoded_packet['payload'].get('raw'):
            raw_data = bytes.fromhex(decoded_packet['payload']['raw']['hex'])
            location = self.location_tracker.analyze_packet_for_location(raw_data, packet.time)
            if location:
                self.root.after(0, self.update_location_display, location)
        
        # Update packet list in GUI thread
        self.root.after(0, self.add_packet_to_list, packet, decoded_packet)
        
        # Update packet count
        count = len(self.packets)
        self.root.after(0, self.packet_count_var.set, f"Packets: {count}")

    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Network Packet Analyzer")
        self.root.geometry("1200x800")

        # Initialize analyzers
        self.detector = EncodingDetector()
        self.packet_decoder = PacketDecoder()
        self.coordinate_analyzer = CoordinateAnalyzer()
        self.payload_decoder = PayloadDecoder()
        self.location_tracker = LocationTracker()  # Add location tracker
        
        # Initialize packet storage
        self.packets = []
        self.original_packets = []
        self.current_packet_index = 0
        
        # Initialize live scanner
        self.scanner = LivePacketScanner(self.process_live_packet)
        self.is_scanning = False

        # Create GUI components
        self.create_gui()
        self.add_protocol_filters()
        self.add_export_options()
        self.setup_live_capture_controls()
        self.setup_protocol_analysis_frame()
        self.setup_location_tracking_frame()  # Add location tracking frame

    def add_packet_to_list(self, packet, decoded_packet=None):
        """Add a single packet to the packet list"""
        try:
            if decoded_packet is None:
                decoded_packet = self.packet_decoder.decode_packet(packet)
            
            time = decoded_packet['timestamp']['formatted']
            
            if 'layer3' in decoded_packet:
                src = decoded_packet['layer3'].get('src_ip', 'Unknown')
                dst = decoded_packet['layer3'].get('dst_ip', 'Unknown')
            else:
                src = "Unknown"
                dst = "Unknown"

            # Get the highest layer protocol
            if decoded_packet.get('layer7', {}).get('protocol'):
                proto = decoded_packet['layer7']['protocol']
            elif decoded_packet.get('layer4', {}).get('type'):
                proto = decoded_packet['layer4']['type']
            else:
                proto = decoded_packet.get('layer3', {}).get('type', 'Unknown')

            length = decoded_packet['raw_data']['length']
            
            self.packet_tree.insert('', 'end', values=(len(self.packets), time, src, dst, proto, length))
            
            # Auto-scroll to bottom
            self.packet_tree.yview_moveto(1)
        except Exception as e:
            print(f"Error adding packet to list: {e}")

    def on_packet_select(self, event):
        """Handle packet selection"""
        selection = self.packet_tree.selection()
        if not selection:
            return

        item = selection[0]
        packet_num = int(self.packet_tree.item(item)['values'][0]) - 1
        packet = self.packets[packet_num]

        # Perform complete packet analysis
        decoded_packet = self.packet_decoder.decode_packet(packet)

        # Update all display areas
        self.update_packet_details(decoded_packet)
        self.update_payload_analysis(decoded_packet)
        self.update_protocol_tabs(decoded_packet)

    def update_packet_details(self, decoded_packet):
        """Update packet details pane"""
        self.details_text.delete(1.0, tk.END)
        
        # Display timestamp
        self.details_text.insert(tk.END, "Timestamp:\n")
        self.format_dict_output(self.details_text, decoded_packet['timestamp'], indent=2)
        self.details_text.insert(tk.END, "\n")

        # Display layer information
        for layer in ['layer2', 'layer3', 'layer4', 'layer7']:
            if layer in decoded_packet:
                self.details_text.insert(tk.END, f"{layer.upper()}:\n")
                self.format_dict_output(self.details_text, decoded_packet[layer], indent=2)
                self.details_text.insert(tk.END, "\n")
    
    def update_payload_analysis(self, decoded_packet):
        """Update payload analysis pane with detailed decoding"""
        self.payload_text.delete(1.0, tk.END)
        
        if 'payload' in decoded_packet and decoded_packet['payload']:
            payload_info = decoded_packet['payload']
            
            if 'raw' in payload_info:
                # Create payload decoder instance
                decoder = PayloadDecoder()
                try:
                    raw_data = bytes.fromhex(payload_info['raw']['hex'])
                    analysis = decoder.analyze_payload(raw_data)
                    
                    # Section 1: Basic Information
                    self.payload_text.insert(tk.END, "BASIC INFORMATION\n")
                    self.payload_text.insert(tk.END, "=" * 70 + "\n")
                    self.payload_text.insert(tk.END, f"Length: {len(raw_data)} bytes\n")
                    self.payload_text.insert(tk.END, f"Entropy: {analysis['entropy']:.2f}\n")
                    if analysis['file_type'] != 'UNKNOWN':
                        self.payload_text.insert(tk.END, f"Detected File Type: {analysis['file_type']}\n")
                    self.payload_text.insert(tk.END, "\n")
                    
                    # Section 2: Hex Dump with Interpretations
                    self.payload_text.insert(tk.END, "HEX DUMP AND INTERPRETATIONS\n")
                    self.payload_text.insert(tk.END, "=" * 70 + "\n")
                    self.payload_text.insert(tk.END, "Offset  Hexadecimal                                              ASCII\n")
                    self.payload_text.insert(tk.END, "-" * 70 + "\n")
                    
                    for line in analysis['hex_dump']:
                        offset = f"{line['offset']:04x}"
                        hex_dump = line['hex'].ljust(48)
                        ascii_dump = line['ascii']
                        
                        self.payload_text.insert(tk.END, f"{offset}  {hex_dump}  {ascii_dump}\n")
                        
                        # Add decoded interpretations if any
                        if line['decoded']:
                            self.payload_text.insert(tk.END, " " * 8 + "Interpreted values:\n")
                            for dtype, value in line['decoded'].items():
                                if isinstance(value, float):
                                    self.payload_text.insert(tk.END, f" " * 10 + f"{dtype}: {value:.6f}\n")
                                else:
                                    self.payload_text.insert(tk.END, f" " * 10 + f"{dtype}: {value}\n")
                    
                    # Section 3: Data Pattern Analysis
                    if analysis['data_analysis']['numbers']:
                        self.payload_text.insert(tk.END, "\nNUMERIC SEQUENCES FOUND\n")
                        self.payload_text.insert(tk.END, "=" * 70 + "\n")
                        for seq in analysis['data_analysis']['numbers']:
                            self.payload_text.insert(tk.END, 
                                f"Offset 0x{seq['offset']:04x}: {seq['type']} = {seq['value']}\n")
                    
                    # Section 4: String Analysis
                    if analysis['data_analysis']['strings']:
                        self.payload_text.insert(tk.END, "\nSTRING SEQUENCES FOUND\n")
                        self.payload_text.insert(tk.END, "=" * 70 + "\n")
                        for string in analysis['data_analysis']['strings']:
                            self.payload_text.insert(tk.END, 
                                f"Offset 0x{string['offset']:04x}: {string['string']} (length: {string['length']})\n")
                    
                    # Section 5: Text Encodings
                    if analysis['text_analysis']:
                        self.payload_text.insert(tk.END, "\nTEXT ENCODING ANALYSIS\n")
                        self.payload_text.insert(tk.END, "=" * 70 + "\n")
                        for encoding, result in analysis['text_analysis'].items():
                            if result['printable_ratio'] > 0.5:  # Only show if mostly printable
                                self.payload_text.insert(tk.END, f"{encoding} ({result['printable_ratio']:.2%} printable):\n")
                                self.payload_text.insert(tk.END, f"{result['text']}\n\n")
                    
                    # Section 6: Repeating Patterns
                    if analysis['data_analysis']['repeating']:
                        self.payload_text.insert(tk.END, "\nREPEATING PATTERNS\n")
                        self.payload_text.insert(tk.END, "=" * 70 + "\n")
                        for pattern in analysis['data_analysis']['repeating']:
                            self.payload_text.insert(tk.END, 
                                f"Offset 0x{pattern['offset']:04x}: Pattern {pattern['pattern']} "
                                f"repeats {pattern['repeats']} times\n")
                    
                    # Section 7: Structure Analysis
                    if analysis['structure_analysis']['boundaries']:
                        self.payload_text.insert(tk.END, "\nSTRUCTURE ANALYSIS\n")
                        self.payload_text.insert(tk.END, "=" * 70 + "\n")
                        for boundary in analysis['structure_analysis']['boundaries']:
                            self.payload_text.insert(tk.END, 
                                f"Boundary marker {boundary['marker']} found at offsets: "
                                f"{', '.join(f'0x{pos:04x}' for pos in boundary['positions'])}\n")
                    
                    # Section 8: Additional Encodings
                    if analysis['encoding_analysis']:
                        self.payload_text.insert(tk.END, "\nADDITIONAL ENCODING ANALYSIS\n")
                        self.payload_text.insert(tk.END, "=" * 70 + "\n")
                        for encoding, result in analysis['encoding_analysis'].items():
                            self.payload_text.insert(tk.END, f"{encoding} decoding:\n")
                            for key, value in result.items():
                                self.payload_text.insert(tk.END, f"  {key}: {value}\n")
                            self.payload_text.insert(tk.END, "\n")

                except Exception as e:
                    self.payload_text.insert(tk.END, f"Error analyzing payload: {str(e)}")
            else:
                self.payload_text.insert(tk.END, "No raw payload data available")
        else:
            self.payload_text.insert(tk.END, "No payload data available")

    def update_protocol_tabs(self, decoded_packet):
        """Update protocol-specific analysis tabs"""
        # Update Protocol Overview tab
        self.protocol_text.delete(1.0, tk.END)
        self.protocol_text.insert(tk.END, "Detected Protocols:\n")
        for proto in decoded_packet['protocols']:
            self.protocol_text.insert(tk.END, f"- {proto}\n")

        # Update HTTP tab
        self.http_text.delete(1.0, tk.END)
        if 'http_analysis' in decoded_packet:
            self.format_dict_output(self.http_text, decoded_packet['http_analysis'])
        else:
            self.http_text.insert(tk.END, "No HTTP data detected")

        # Update DNS tab
        self.dns_text.delete(1.0, tk.END)
        if 'dns_analysis' in decoded_packet:
            self.format_dict_output(self.dns_text, decoded_packet['dns_analysis'])
        else:
            self.dns_text.insert(tk.END, "No DNS data detected")

        # Update TLS tab
        self.tls_text.delete(1.0, tk.END)
        if 'tls_analysis' in decoded_packet:
            self.format_dict_output(self.tls_text, decoded_packet['tls_analysis'])
        else:
            self.tls_text.insert(tk.END, "No TLS/SSL data detected")

    def format_dict_output(self, text_widget, data, indent=0):
        """Format dictionary output for text widgets"""
        indent_str = " " * indent
        if isinstance(data, dict):
            for key, value in data.items():
                text_widget.insert(tk.END, f"{indent_str}{key}:\n")
                if isinstance(value, (dict, list)):
                    self.format_dict_output(text_widget, value, indent + 2)
                else:
                    text_widget.insert(tk.END, f"{indent_str}  {value}\n")
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    self.format_dict_output(text_widget, item, indent + 2)
                else:
                    text_widget.insert(tk.END, f"{indent_str}- {item}\n")
        else:
            text_widget.insert(tk.END, f"{indent_str}{data}\n")

    def apply_quick_filter(self, protocol):
        """Apply quick filter for specific protocols"""
        if protocol == "TCP":
            self.packets = [p for p in self.original_packets if scapy.TCP in p]
        elif protocol == "UDP":
            self.packets = [p for p in self.original_packets if scapy.UDP in p]
        elif protocol == "HTTP":
            self.packets = [p for p in self.original_packets if scapy.TCP in p and
                          (p[scapy.TCP].sport == 80 or p[scapy.TCP].dport == 80 or
                           p[scapy.TCP].sport == 443 or p[scapy.TCP].dport == 443)]
        elif protocol == "DNS":
            self.packets = [p for p in self.original_packets if scapy.UDP in p and
                          (p[scapy.UDP].sport == 53 or p[scapy.UDP].dport == 53)]

        self.update_packet_list()
        self.status_var.set(f"Filtered: showing {len(self.packets)} {protocol} packets")

    def reset_filters(self):
        """Reset to original packet list"""
        self.packets = self.original_packets.copy()
        self.update_packet_list()
        self.status_var.set(f"Filters reset: showing all {len(self.packets)} packets")

    def open_pcap(self):
        """Open and load a PCAP file"""
        filename = filedialog.askopenfilename(
            filetypes=[
                ("PCAP files", "*.pcap;*.pcapng"),
                ("All files", "*.*")
            ]
        )
        if filename:
            self.status_var.set("Loading PCAP file...")
            self.root.update()

            # Use threading to prevent GUI freeze
            thread = threading.Thread(target=self.load_pcap, args=(filename,))
            thread.daemon = True
            thread.start()

    def load_pcap(self, filename):
        """Load packets from PCAP file"""
        try:
            self.packets = scapy.rdpcap(filename)
            self.original_packets = self.packets.copy()
            
            # Pre-decode all packets
            decoded_packets = []
            for packet in self.packets:
                try:
                    decoded = self.packet_decoder.decode_packet(packet)
                    decoded_packets.append(decoded)
                except Exception as e:
                    print(f"Error decoding packet: {e}")
                    decoded_packets.append(None)

            self.root.after(0, lambda: self.update_packet_list_with_decoded(decoded_packets))
            self.root.after(0, lambda: self.status_var.set(f"Loaded {len(self.packets)} packets"))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to load PCAP: {str(e)}"))
            self.root.after(0, lambda: self.status_var.set("Error loading PCAP"))

    def update_packet_list_with_decoded(self, decoded_packets):
        """Update packet list with pre-decoded packet information"""
        self.packet_tree.delete(*self.packet_tree.get_children())
        for i, (packet, decoded) in enumerate(zip(self.packets, decoded_packets), 1):
            try:
                if decoded:
                    time = decoded['timestamp']['formatted']
                    src = decoded.get('layer3', {}).get('src_ip', 'Unknown')
                    dst = decoded.get('layer3', {}).get('dst_ip', 'Unknown')
                    proto = decoded.get('layer7', {}).get('protocol', decoded.get('layer4', {}).get('type', 'Unknown'))
                    length = decoded['raw_data']['length']
                else:
                    # Fallback if decoding failed
                    time = datetime.fromtimestamp(float(packet.time)).strftime('%H:%M:%S.%f')
                    src = packet[scapy.IP].src if scapy.IP in packet else "Unknown"
                    dst = packet[scapy.IP].dst if scapy.IP in packet else "Unknown"
                    proto = "TCP" if scapy.TCP in packet else "UDP" if scapy.UDP in packet else "Unknown"
                    length = len(packet)

                self.packet_tree.insert('', 'end', values=(i, time, src, dst, proto, length))
            except Exception as e:
                print(f"Error updating packet list: {e}")

    def apply_filter(self):
        """Apply custom filter to packets"""
        filter_text = self.filter_var.get().strip()
        if not filter_text:
            self.reset_filters()
            return

        try:
            filtered_packets = []
            for packet in self.original_packets:
                # Create filter map for evaluation
                filter_map = {
                    'TCP': scapy.TCP in packet,
                    'UDP': scapy.UDP in packet,
                    'IP': scapy.IP in packet,
                    'src_ip': packet[scapy.IP].src if scapy.IP in packet else None,
                    'dst_ip': packet[scapy.IP].dst if scapy.IP in packet else None,
                    'src_port': packet[scapy.TCP].sport if scapy.TCP in packet else None,
                    'dst_port': packet[scapy.TCP].dport if scapy.TCP in packet else None,
                }

                try:
                    if eval(filter_text, {}, filter_map):
                        filtered_packets.append(packet)
                except:
                    continue

            self.packets = filtered_packets
            self.update_packet_list()
            self.status_var.set(f"Showing {len(filtered_packets)} filtered packets")
        except Exception as e:
            messagebox.showerror("Filter Error", f"Invalid filter: {str(e)}")

    def export_to_json(self):
        """Export packet analysis to JSON format"""
        if not self.packets:
            messagebox.showwarning("Warning", "No packets to export")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )

        if filename:
            try:
                packet_data = []
                for packet in self.packets:
                    # Get complete packet analysis
                    decoded = self.packet_decoder.decode_packet(packet)
                    packet_data.append(decoded)

                with open(filename, 'w') as f:
                    json.dump(packet_data, f, indent=2, default=str)

                messagebox.showinfo("Success", "Data exported successfully")
                self.status_var.set("Data exported to JSON")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export data: {str(e)}")

    def save_analysis(self):
        """Save detailed analysis to a text file"""
        if not self.packets:
            messagebox.showwarning("Warning", "No packets to save")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )

        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write("Network Packet Analysis Report\n")
                    f.write("=" * 50 + "\n\n")

                    # Write summary statistics
                    f.write("Summary Statistics:\n")
                    f.write("-" * 20 + "\n")
                    f.write(f"Total Packets: {len(self.packets)}\n")
                    protocol_counts = {
                        'TCP': sum(1 for p in self.packets if scapy.TCP in p),
                        'UDP': sum(1 for p in self.packets if scapy.UDP in p),
                        'HTTP': sum(1 for p in self.packets if scapy.TCP in p and 
                                  (p[scapy.TCP].sport in (80, 443) or p[scapy.TCP].dport in (80, 443))),
                        'DNS': sum(1 for p in self.packets if scapy.UDP in p and 
                                 (p[scapy.UDP].sport == 53 or p[scapy.UDP].dport == 53))
                    }
                    for proto, count in protocol_counts.items():
                        f.write(f"{proto} Packets: {count}\n")
                    f.write("\n")

                    # Write detailed packet analysis
                    for i, packet in enumerate(self.packets, 1):
                        f.write(f"\nPacket {i}\n")
                        f.write("-" * 50 + "\n")
                        
                        # Get complete packet analysis
                        decoded = self.packet_decoder.decode_packet(packet)
                        
                        # Write timestamp
                        f.write(f"Timestamp: {decoded['timestamp']['formatted']}\n")
                        
                        # Write layer information
                        for layer in ['layer2', 'layer3', 'layer4', 'layer7']:
                            if layer in decoded:
                                f.write(f"\n{layer.upper()}:\n")
                                self.write_dict_to_file(f, decoded[layer], indent=2)
                        
                        # Write payload analysis
                        if 'payload' in decoded and decoded['payload']:
                            f.write("\nPayload Analysis:\n")
                            self.write_dict_to_file(f, decoded['payload'], indent=2)
                        
                        f.write("\n" + "=" * 50 + "\n")

                messagebox.showinfo("Success", "Analysis saved successfully")
                self.status_var.set("Analysis saved to file")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save analysis: {str(e)}")

    def write_dict_to_file(self, file, data, indent=0):
        """Write dictionary data to file with formatting"""
        indent_str = " " * indent
        if isinstance(data, dict):
            for key, value in data.items():
                file.write(f"{indent_str}{key}:\n")
                if isinstance(value, (dict, list)):
                    self.write_dict_to_file(file, value, indent + 2)
                else:
                    file.write(f"{indent_str}  {value}\n")
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    self.write_dict_to_file(file, item, indent + 2)
                else:
                    file.write(f"{indent_str}- {item}\n")
        else:
            file.write(f"{indent_str}{data}\n")

    def load_coordinate_csv(self):
        """Load coordinate CSV file for analysis"""
        filename = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if filename:
            try:
                self.coordinate_analyzer.load_csv(filename)
                self.status_var.set(f"Loaded coordinate CSV file")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def analyze_coordinates(self):
        """Perform coordinate analysis on packets"""
        if not hasattr(self, 'packets') or not self.packets:
            messagebox.showwarning("Warning", "No packets loaded")
            return
        
        if self.coordinate_analyzer.csv_data is None:
            messagebox.showwarning("Warning", "Please load coordinate CSV file first")
            return

        results_window = tk.Toplevel(self.root)
        results_window.title("Coordinate Analysis Results")
        results_window.geometry("800x600")
        
        # Add search/filter entry
        filter_frame = ttk.Frame(results_window)
        filter_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(filter_frame, text="Filter:").pack(side='left', padx=2)
        filter_entry = ttk.Entry(filter_frame)
        filter_entry.pack(side='left', fill='x', expand=True, padx=2)
        
        # Results text widget
        results_text = scrolledtext.ScrolledText(results_window)
        results_text.pack(fill='both', expand=True, padx=5, pady=5)

        total_matches = 0
        try:
            csv_data = self.coordinate_analyzer.csv_data
            csv_data['ID'] = pd.to_numeric(csv_data['ID'], errors='coerce')

            results_text.insert('end', "Analyzing packets for coordinate matches...\n\n")
            results_text.update()

            for packet_index, packet in enumerate(self.packets, 1):
                decoded = self.packet_decoder.decode_packet(packet)
                
                if 'payload' not in decoded or not decoded['payload']:
                    continue

                payload = bytes.fromhex(decoded['payload']['raw']['hex'])
                coords = self.coordinate_analyzer.find_coordinates(payload, decoded['timestamp']['epoch'])
                
                if coords:
                    for coord in coords:
                        matches = csv_data[
                            (abs(csv_data['ID'] - coord['timestamp']) < 0.1) &
                            (abs(csv_data['x'] - coord['x']) < 0.001) &
                            (abs(csv_data['y'] - coord['y']) < 0.001) &
                            (abs(csv_data['z'] - coord['z']) < 0.001)
                        ]

                        if not matches.empty:
                            total_matches += 1
                            results_text.insert('end',
                                f"\nMatch #{total_matches}:\n"
                                f"Packet #{packet_index}\n"
                                f"Time: {decoded['timestamp']['formatted']}\n"
                                f"Format: {coord['format']}\n"
                                f"Offset: {coord['offset']}\n"
                                f"Coordinates: ({coord['x']:.3f}, {coord['y']:.3f}, {coord['z']:.3f})\n"
                                f"Matching CSV IDs: {', '.join(map(str, matches['ID'].tolist()))}\n"
                                f"{'='*50}\n"
                            )
                            results_text.see('end')
                            results_text.update()

            if total_matches == 0:
                results_text.insert('end', "No matching coordinates found.\n")
            results_text.insert('1.0', f"Analysis complete: Found {total_matches} matching coordinates.\n{'='*50}\n\n")
            
            self.status_var.set(f"Coordinate analysis complete: {total_matches} matches found")

        except Exception as e:
            messagebox.showerror("Error", f"Coordinate analysis failed: {str(e)}")

class PayloadDecoder:
    def __init__(self):
        self.known_signatures = {
            b'\x1f\x8b\x08': 'GZIP',
            b'\x42\x5a\x68': 'BZIP2',
            b'\x50\x4b\x03\x04': 'ZIP',
            b'\x00\x00\x00\x14\x66\x74\x79\x70': 'MP4',
            b'\x47\x49\x46\x38': 'GIF',
            b'\x89\x50\x4e\x47': 'PNG',
            b'\xff\xd8\xff': 'JPEG',
            b'\x25\x50\x44\x46': 'PDF',
            b'\x7f\x45\x4c\x46': 'ELF',
            b'\x4d\x5a': 'EXE',
            b'\x23\x21': 'SHELL SCRIPT',
            b'\x43\x57\x53': 'SWF',
            b'\x46\x4c\x56': 'FLV',
            b'\x52\x49\x46\x46': 'RIFF',
        }
        
        self.data_patterns = {
            'float32_le': struct.Struct('<f'),
            'float32_be': struct.Struct('>f'),
            'float64_le': struct.Struct('<d'),
            'float64_be': struct.Struct('>d'),
            'int32_le': struct.Struct('<i'),
            'int32_be': struct.Struct('>i'),
            'uint32_le': struct.Struct('<I'),
            'uint32_be': struct.Struct('>I'),
            'int16_le': struct.Struct('<h'),
            'int16_be': struct.Struct('>h'),
            'uint16_le': struct.Struct('<H'),
            'uint16_be': struct.Struct('>H'),
        }

    def analyze_payload(self, data: bytes) -> dict:
        """Comprehensive payload analysis"""
        result = {
            'length': len(data),
            'hex_dump': self.create_hex_dump(data),
            'file_type': self.detect_file_type(data),
            'data_analysis': self.analyze_data_patterns(data),
            'text_analysis': self.analyze_text(data),
            'entropy': self.calculate_entropy(data),
            'encoding_analysis': self.analyze_encodings(data),
            'structure_analysis': self.analyze_structure(data)
        }
        return result

    def create_hex_dump(self, data: bytes) -> list:
        """Create formatted hex dump with metadata"""
        hex_dump = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_line = {
                'offset': i,
                'hex': ' '.join(f'{b:02X}' for b in chunk),
                'ascii': ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk),
                'decoded': self.try_decode_chunk(chunk)
            }
            hex_dump.append(hex_line)
        return hex_dump

    def try_decode_chunk(self, chunk: bytes) -> dict:
        """Try to decode each chunk in various ways"""
        decoded = {}
        
        # Try different numeric interpretations
        for name, pattern in self.data_patterns.items():
            if len(chunk) >= pattern.size:
                try:
                    value = pattern.unpack(chunk[:pattern.size])[0]
                    if isinstance(value, float):
                        if -1e10 < value < 1e10:  # Reasonable range check
                            decoded[name] = value
                    else:
                        decoded[name] = value
                except:
                    pass

        # Try text decodings
        encodings = ['utf-8', 'ascii', 'utf-16', 'utf-32']
        for encoding in encodings:
            try:
                text = chunk.decode(encoding)
                if any(32 <= ord(c) <= 126 for c in text):  # Contains printable chars
                    decoded[encoding] = text
            except:
                pass

        return decoded

    def detect_file_type(self, data: bytes) -> str:
        """Detect file type based on signatures and content analysis"""
        # Check for known file signatures
        for signature, filetype in self.known_signatures.items():
            if data.startswith(signature):
                return filetype

        # Additional content-based detection
        if data.startswith(b'<?xml'):
            return 'XML'
        elif data.startswith(b'{') and data.strip().endswith(b'}'):
            try:
                json.loads(data)
                return 'JSON'
            except:
                pass
        elif all(b in range(256) for b in data[:4]) and len(set(data[:4])) > 2:
            return 'BINARY'
            
        return 'UNKNOWN'

    def analyze_data_patterns(self, data: bytes) -> dict:
        """Analyze for common data patterns"""
        patterns = {
            'numbers': self.find_number_sequences(data),
            'strings': self.find_string_sequences(data),
            'repeating': self.find_repeating_patterns(data),
            'structured': self.detect_structured_data(data)
        }
        return patterns

    def find_number_sequences(self, data: bytes) -> list:
        """Find sequences of numbers in different formats"""
        sequences = []
        # Check for different numeric patterns
        for i in range(0, len(data) - 4):
            chunk = data[i:i+4]
            for name, pattern in self.data_patterns.items():
                try:
                    if len(chunk) >= pattern.size:
                        value = pattern.unpack(chunk[:pattern.size])[0]
                        if isinstance(value, float):
                            if -1e10 < value < 1e10:  # Reasonable range
                                sequences.append({
                                    'offset': i,
                                    'type': name,
                                    'value': value
                                })
                        elif isinstance(value, int):
                            sequences.append({
                                'offset': i,
                                'type': name,
                                'value': value
                            })
                except:
                    continue
        return sequences

    def find_string_sequences(self, data: bytes) -> list:
        """Find viable string sequences"""
        strings = []
        current_string = []
        current_offset = None

        for i, byte in enumerate(data):
            if 32 <= byte <= 126:  # Printable ASCII
                if current_string == []:
                    current_offset = i
                current_string.append(chr(byte))
            else:
                if len(current_string) >= 4:  # Min string length
                    strings.append({
                        'offset': current_offset,
                        'string': ''.join(current_string),
                        'length': len(current_string)
                    })
                current_string = []
                current_offset = None

        # Don't forget last string
        if len(current_string) >= 4:
            strings.append({
                'offset': current_offset,
                'string': ''.join(current_string),
                'length': len(current_string)
            })

        return strings

    def find_repeating_patterns(self, data: bytes) -> list:
        """Find repeating byte patterns"""
        patterns = []
        min_pattern_len = 2
        max_pattern_len = 8

        for pattern_len in range(min_pattern_len, max_pattern_len + 1):
            for i in range(len(data) - pattern_len * 2):
                pattern = data[i:i+pattern_len]
                # Look for at least 3 repetitions
                repeats = 1
                pos = i + pattern_len
                while pos < len(data) - pattern_len and data[pos:pos+pattern_len] == pattern:
                    repeats += 1
                    pos += pattern_len
                
                if repeats >= 3:
                    patterns.append({
                        'offset': i,
                        'pattern': pattern.hex(),
                        'length': pattern_len,
                        'repeats': repeats
                    })
                    i = pos  # Skip past this pattern

        return patterns

    def detect_structured_data(self, data: bytes) -> dict:
        """Detect potential structured data formats"""
        structure = {
            'potential_headers': [],
            'field_separators': [],
            'record_sizes': []
        }

        # Look for common field separators
        separators = [b',', b'|', b'\t', b';']
        for sep in separators:
            count = data.count(sep)
            if count > 1:
                structure['field_separators'].append({
                    'separator': sep.hex(),
                    'count': count
                })

        # Look for potential record sizes
        if len(data) >= 8:
            for size in range(4, 17):  # Common record sizes
                if len(data) % size == 0:
                    # Verify some consistency in the structure
                    consistency = 0
                    for i in range(0, len(data) - size, size):
                        if data[i] == data[i + size]:
                            consistency += 1
                    if consistency >= 2:
                        structure['record_sizes'].append({
                            'size': size,
                            'count': len(data) // size,
                            'consistency': consistency
                        })

        return structure

    def analyze_text(self, data: bytes) -> dict:
        """Analyze text representations"""
        text_analysis = {}
        
        # Try different encodings
        encodings = ['utf-8', 'ascii', 'utf-16', 'utf-32', 'iso-8859-1']
        for encoding in encodings:
            try:
                decoded = data.decode(encoding)
                if any(32 <= ord(c) <= 126 for c in decoded):  # Contains printable chars
                    text_analysis[encoding] = {
                        'text': decoded,
                        'printable_ratio': sum(32 <= ord(c) <= 126 for c in decoded) / len(decoded)
                    }
            except:
                continue

        return text_analysis

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of the data"""
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = data.count(bytes([x])) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy

    def analyze_encodings(self, data: bytes) -> dict:
        """Analyze possible encodings"""
        encodings = {}
        
        # Try base64
        try:
            decoded = base64.b64decode(data + b'=' * (-len(data) % 4))
            encodings['base64'] = {
                'decoded': decoded.hex(),
                'text': self.try_decode_chunk(decoded)
            }
        except:
            pass

        # Try hex
        try:
            hex_str = data.hex()
            if all(c in '0123456789abcdefABCDEF' for c in hex_str):
                encodings['hex'] = {
                    'text': hex_str,
                    'decoded': bytes.fromhex(hex_str).hex()
                }
        except:
            pass

        # Try URL encoding
        try:
            from urllib.parse import unquote
            decoded = unquote(data.decode())
            if '%' in decoded:
                encodings['url'] = {
                    'decoded': decoded
                }
        except:
            pass

        return encodings

    def analyze_structure(self, data: bytes) -> dict:
        """Analyze data structure patterns"""
        structure = {
            'patterns': {},
            'alignment': {},
            'boundaries': []
        }

        # Check byte alignment patterns
        alignments = [2, 4, 8]
        for align in alignments:
            aligned_positions = []
            for i in range(0, len(data) - align, align):
                chunk = data[i:i+align]
                if all(x == chunk[0] for x in chunk):
                    aligned_positions.append(i)
            if aligned_positions:
                structure['alignment'][align] = aligned_positions

        # Look for boundary markers
        common_boundaries = [b'\x00\x00', b'\xff\xff', b'\r\n', b'\n\n']
        for boundary in common_boundaries:
            positions = []
            pos = -1
            while True:
                pos = data.find(boundary, pos + 1)
                if pos == -1:
                    break
                positions.append(pos)
            if positions:
                structure['boundaries'].append({
                    'marker': boundary.hex(),
                    'positions': positions
                })

        return structure


class LocationTracker:
    def __init__(self):
        self.locations = []
        self.current_location = None
        self.log_file = None
        
    def start_logging(self, filename="location_log.csv"):
        """Start logging locations to CSV file"""
        self.log_file = open(filename, 'w')
        self.log_file.write("Timestamp,X,Y,Z,Packet_Offset,Raw_Hex\n")

    def stop_logging(self):
        """Stop logging and close file"""
        if self.log_file:
            self.log_file.close()
            self.log_file = None

    def analyze_packet_for_location(self, packet_data: bytes, timestamp: float) -> dict:
        """Analyze packet data for location coordinates"""
        result = None
        
        # Search for the location pattern
        for i in range(len(packet_data) - 12):  # Need at least 12 bytes for 3 float32s
            try:
                x = struct.unpack('<f', packet_data[i:i+4])[0]
                y = struct.unpack('<f', packet_data[i+4:i+8])[0]
                z = struct.unpack('<f', packet_data[i+8:i+12])[0]
                
                # Check if these values are within reasonable game coordinates
                # Adjust these ranges based on your game's coordinate system
                if (2000 < x < 3000 and  # X range
                    0 < y < 1000 and     # Y range
                    1500 < z < 2500):    # Z range
                    
                    result = {
                        'timestamp': timestamp,
                        'x': x,
                        'y': y,
                        'z': z,
                        'offset': i,
                        'raw_hex': packet_data[i:i+12].hex()
                    }
                    
                    # Log the location if logging is enabled
                    if self.log_file:
                        self.log_file.write(f"{datetime.fromtimestamp(timestamp).isoformat()},{x},{y},{z},{i},{result['raw_hex']}\n")
                        self.log_file.flush()  # Ensure it's written immediately
                    
                    self.current_location = result
                    self.locations.append(result)
                    return result
                    
            except Exception as e:
                continue
                
        return result

    def get_location_history(self, limit=10):
        """Get recent location history"""
        return self.locations[-limit:] if self.locations else []

    def get_current_location(self):
        """Get most recent location"""
        return self.current_location

def main():
    root = tk.Tk()
    app = PacketAnalyzerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()