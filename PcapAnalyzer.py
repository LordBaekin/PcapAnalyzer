import tkinter as tk  
from tkinter import ttk, filedialog, scrolledtext, messagebox  
import scapy.all as scapy  
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
  
class CoordinateAnalyzer:  
   def __init__(self):  
      self.formats = {  
        'float32': '<fff',  # Little-endian, 3 floats  
        'float64': '<ddd',  # Little-endian, 3 doubles  
        'int32': '<iii'    # Little-endian, 3 integers  
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
  
      self.detector = EncodingDetector()  
      self.packets = []  
      self.original_packets = []  # Store original packets for filter reset  
      self.current_packet_index = 0  
      self.coordinate_analyzer = CoordinateAnalyzer()  
  
      self.create_gui()  
      self.add_protocol_filters()  
      self.add_export_options()  
  
   def create_gui(self):  
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
  
      # Right panel - Packet Details and Payload  
      right_frame = ttk.Frame(paned_window)  
  
      # Packet details  
      details_frame = ttk.LabelFrame(right_frame, text="Packet Details")  
      self.details_text = scrolledtext.ScrolledText(details_frame, height=10)  
      self.details_text.pack(fill='both', expand=True, padx=5, pady=5)  
      details_frame.pack(fill='both', expand=True, padx=5, pady=5)  
  
      # Payload analysis  
      payload_frame = ttk.LabelFrame(right_frame, text="Payload Analysis")  
      self.payload_text = scrolledtext.ScrolledText(payload_frame, height=10)  
      self.payload_text.pack(fill='both', expand=True, padx=5, pady=5)  
      payload_frame.pack(fill='both', expand=True, padx=5, pady=5)  
  
      paned_window.add(right_frame, weight=2)  
  
      # Status bar  
      self.status_var = tk.StringVar()  
      status_bar = ttk.Label(main_container, textvariable=self.status_var, relief='sunken', anchor='w')  
      status_bar.pack(fill='x', pady=2)  
  
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
      try:  
        self.packets = scapy.rdpcap(filename)  
        self.original_packets = self.packets.copy()  # Store original packets for filter reset  
        self.root.after(0, self.update_packet_list)  
        self.root.after(0, lambda: self.status_var.set(f"Loaded {len(self.packets)} packets"))  
      except Exception as e:  
        self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to load PCAP: {str(e)}"))  
        self.root.after(0, lambda: self.status_var.set("Error loading PCAP"))  
  
   def update_packet_list(self):  
      self.packet_tree.delete(*self.packet_tree.get_children())  
      for i, packet in enumerate(self.packets, 1):  
        try:  
           time = datetime.fromtimestamp(float(packet.time)).strftime('%H:%M:%S.%f')  
           if scapy.IP in packet:  
              src = packet[scapy.IP].src  
              dst = packet[scapy.IP].dst  
           else:  
              src = "Unknown"  
              dst = "Unknown"  
  
           proto = "Unknown"  
           if scapy.TCP in packet:  
              proto = "TCP"  
           elif scapy.UDP in packet:  
              proto = "UDP"  
  
           length = len(packet)  
  
           self.packet_tree.insert('', 'end', values=(i, time, src, dst, proto, length))  
        except Exception as e:  
           print(f"Error processing packet {i}: {e}")  
  
   def on_packet_select(self, event):  
      selection = self.packet_tree.selection()  
      if not selection:  
        return  
  
      item = selection[0]  
      packet_num = int(self.packet_tree.item(item)['values'][0]) - 1  
      packet = self.packets[packet_num]  
  
      # Update packet details  
      self.details_text.delete(1.0, tk.END)  
      self.details_text.insert(tk.END, packet.show(dump=True))  
  
      # Update payload analysis  
      self.payload_text.delete(1.0, tk.END)  
  
      if scapy.TCP in packet:  
        payload = bytes(packet[scapy.TCP].payload)  
      elif scapy.UDP in packet:  
        payload = bytes(packet[scapy.UDP].payload)  
      else:  
        payload = b""  
  
      if payload:  
        self.payload_text.insert(tk.END, "Raw Payload:\n")  
        self.payload_text.insert(tk.END, f"Hex: {payload.hex()}\n")  
        self.payload_text.insert(tk.END, f"Length: {len(payload)} bytes\n\n")  
  
        self.payload_text.insert(tk.END, "ASCII Representation:\n")  
        ascii_text = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in payload)  
        self.payload_text.insert(tk.END, ascii_text + "\n\n")  
  
        self.payload_text.insert(tk.END, "Detected Encodings:\n")  
        encodings = self.detector.detect_encoding(payload)  
        if encodings:  
           for encoding, decoded, confidence in encodings:  
              self.payload_text.insert(tk.END, f"- {encoding} (confidence: {confidence:.2f})\n")  
              if decoded:  
                if isinstance(decoded, bytes):  
                   try:  
                      decoded_str = decoded.decode('utf-8', errors='ignore')  
                      self.payload_text.insert(tk.END, f"  Decoded (UTF-8): {decoded_str}\n")  
                      self.payload_text.insert(tk.END, f"  Decoded (Hex): {decoded.hex()}\n")  
                   except:  
                      self.payload_text.insert(tk.END, f"  Decoded (Hex): {decoded.hex()}\n")  
                else:  
                   self.payload_text.insert(tk.END, f"  Decoded: {decoded}\n")  
        else:  
           self.payload_text.insert(tk.END, "No encodings detected.\n")  
  
        if self.coordinate_analyzer.csv_data is not None:  
           coords = self.coordinate_analyzer.find_coordinates(payload, packet.time)  
           if coords:  
              self.payload_text.insert(tk.END, "\nPotential Coordinates Found:\n")  
              for coord in coords:  
                self.payload_text.insert(tk.END,  
                   f"Format: {coord['format']}\n"  
                   f"Offset: {coord['offset']}\n"  
                   f"Coordinates: ({coord['x']}, {coord['y']}, {coord['z']})\n"  
                )  
  
   def apply_filter(self):  
      filter_text = self.filter_var.get().strip()  
      if not filter_text:  
        self.reset_filters()  
        return  
  
      try:  
        filtered_packets = []  
        for packet in self.original_packets:  
           # Use a dictionary to map filter keywords to packet attributes  
           filter_map = {  
              'TCP': scapy.TCP in packet,  
              'UDP': scapy.UDP in packet,  
              'IP': scapy.IP in packet,  
              'src_ip': packet[scapy.IP].src if scapy.IP in packet else None,  
              'dst_ip': packet[scapy.IP].dst if scapy.IP in packet else None,  
              'src_port': packet[scapy.TCP].sport if scapy.TCP in packet else None,  
              'dst_port': packet[scapy.TCP].dport if scapy.TCP in packet else None,  
           }  
  
           # Evaluate the filter string using the filter map  
           if eval(filter_text, filter_map):  
              filtered_packets.append(packet)  
  
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
              packet_info = {  
                'time': packet.time,  
                'length': len(packet),  
                'protocols': [],  
                'payload': None,  
                'encodings': []  
              }  
  
              if scapy.IP in packet:  
                packet_info['source_ip'] = packet[scapy.IP].src  
                packet_info['dest_ip'] = packet[scapy.IP].dst  
  
              if scapy.TCP in packet:  
                packet_info['protocols'].append('TCP')  
                packet_info['source_port'] = packet[scapy.TCP].sport  
                packet_info['dest_port'] = packet[scapy.TCP].dport  
                payload = bytes(packet[scapy.TCP].payload)  
              elif scapy.UDP in packet:  
                packet_info['protocols'].append('UDP')  
                packet_info['source_port'] = packet[scapy.UDP].sport  
                packet_info['dest_port'] = packet[scapy.UDP].dport  
                payload = bytes(packet[scapy.UDP].payload)  
              else:  
                payload = b""  
  
              if payload:  
                packet_info['payload'] = {  
                   'hex': payload.hex(),  
                   'ascii': ''.join(chr(b) if 32 <= b <= 126 else '.' for b in payload)  
                }  
                encodings = self.detector.detect_encoding(payload)  
                packet_info['encodings'] = [  
                   {'type': enc, 'confidence': conf}  
                   for enc, _, conf in encodings  
                ]  
  
              packet_data.append(packet_info)  
  
           with open(filename, 'w') as f:  
              json.dump(packet_data, f, indent=2)  
  
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
              f.write(f"TCP Packets: {sum(1 for p in self.packets if scapy.TCP in p)}\n")  
              f.write(f"UDP Packets: {sum(1 for p in self.packets if scapy.UDP in p)}\n\n")  
  
              # Write detailed packet analysis  
              for i, packet in enumerate(self.packets, 1):  
                f.write(f"\nPacket {i}\n")  
                f.write("-" * 50 + "\n")  
                f.write(packet.show(dump=True))  
                f.write("\n")  
  
                if scapy.TCP in packet or scapy.UDP in packet:  
                   if scapy.TCP in packet:  
                      payload = bytes(packet[scapy.TCP].payload)  
                   else:  
                      payload = bytes(packet[scapy.UDP].payload)  
  
                   if payload:  
                      f.write("\nPayload Analysis:\n")  
                      f.write(f"Raw Hex: {payload.hex()}\n")  
                      f.write(f"ASCII: {''.join(chr(b) if 32 <= b <= 126 else '.' for b in payload)}\n")  
  
                      encodings = self.detector.detect_encoding(payload)  
                      if encodings:  
                        f.write("\nDetected Encodings:\n")  
                        for encoding, decoded, confidence in encodings:  
                           f.write(f"- {encoding} (confidence: {confidence:.2f})\n")  
                           if decoded:  
                              f.write(f"  Decoded: {decoded}\n")  
  
           messagebox.showinfo("Success", "Analysis saved successfully")  
           self.status_var.set("Analysis saved to file")  
        except Exception as e:  
           messagebox.showerror("Error", f"Failed to save analysis: {str(e)}")  
  
   def load_coordinate_csv(self):  
      filename = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])  
      if filename:  
        try:  
           self.coordinate_analyzer.load_csv(filename)  
           self.status_var.set(f"Loaded coordinate CSV file")  
        except Exception as e:  
           messagebox.showerror("Error", str(e))  
  
   def analyze_coordinates(self):  
       if not hasattr(self, 'packets') or not self.packets:  
          messagebox.showwarning("Warning", "No packets loaded")  
          return  
       
       if self.coordinate_analyzer.csv_data is None:  
          messagebox.showwarning("Warning", "Please load coordinate CSV file first")  
          return  
  
       results_window = tk.Toplevel(self.root)  
       results_window.title("Coordinate Analysis Results")  
       results_text = scrolledtext.ScrolledText(results_window)  
       results_text.pack(fill='both', expand=True)  
  
       total_matches = 0  
  
       try:  
          csv_data = self.coordinate_analyzer.csv_data  
          csv_data['ID'] = pd.to_numeric(csv_data['ID'], errors='coerce')  
  
          for packet in self.packets:  
            if scapy.TCP in packet:  
               payload = bytes(packet[scapy.TCP].payload)  
            elif scapy.UDP in packet:  
               payload = bytes(packet[scapy.UDP].payload)  
            else:  
               continue  
  
            coords = self.coordinate_analyzer.find_coordinates(payload, packet.time)  
            if coords:  
               for coord in coords:  
                  csv_time = coord['timestamp']  
                  matches = csv_data[  
                    (abs(csv_data['ID'] - csv_time) < 0.1) &  
                    (abs(csv_data['x'] - coord['x']) < 0.001) &  
                    (abs(csv_data['y'] - coord['y']) < 0.001) &  
                    (abs(csv_data['z'] - coord['z']) < 0.001)  
                  ]  
  
                  if not matches.empty:  
                    total_matches += 1  
                    packet_time = datetime.fromtimestamp(float(packet.time)).strftime('%H:%M:%S.%f')  
                    results_text.insert('end',  
                       f"\nMatch #{total_matches}:\n"  
                       f"Packet Time: {packet_time}\n"  
                       f"Format: {coord['format']}\n"  
                       f"Offset: {coord['offset']}\n"  
                       f"Coordinates: ({coord['x']:.3f}, {coord['y']:.3f}, {coord['z']:.3f})\n"  
                       f"Matching CSV IDs: {', '.join(map(str, matches['ID'].tolist()))}\n"  
                       f"{'='*50}\n"  
                    )  
  
          if total_matches == 0:  
            results_text.insert('end', "No matching coordinates found.\n")  
          else:  
            results_text.insert('1.0', f"Found {total_matches} matching coordinates.\n{'='*50}\n\n")  
          
          self.status_var.set(f"Coordinate analysis complete: {total_matches} matches found")  
  
       except Exception as e:  
          messagebox.showerror("Error", f"Coordinate analysis failed: {str(e)}")
  
  
def main():  
   root = tk.Tk()  
   app = PacketAnalyzerGUI(root)  
   root.mainloop()  
  
if __name__ == "__main__":  
   main()
