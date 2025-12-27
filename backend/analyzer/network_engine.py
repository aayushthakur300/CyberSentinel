from scapy.all import rdpcap, IP, TCP, UDP, Raw
from io import BytesIO
import collections
# Import your AI Engine
from analyzer.ai_explainer import generate_explanation
# 🔥 CRITICAL: Connect Network Engine to the MITRE Brain
try:
    from .mitre_mapping import get_mitre_tag, MITRE_SIGNATURES
except ImportError:
    # Fallback for standalone testing
    def get_mitre_tag(k, m): return f"[GENERIC] {m}"
    MITRE_SIGNATURES = {}

def analyze_pcap(file_content):
    """
    Analyzes PCAP data for suspicious Ports AND suspicious Payloads (DPI).
    Scans every packet against the MITRE Matrix for 50+ threats.
    """
    # 1. Setup Scapy
    pcap_file = BytesIO(file_content)
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        return {
            "packet_count": 0,
            "protocols": {},
            "suspicious_ports": [],
            "suspicious_payloads": [f"Error parsing PCAP: {str(e)}"]
        }
    
    stats = {
        "packet_count": len(packets),
        "protocols": collections.Counter(),
        "ips": collections.Counter(),
        "suspicious_ports": [],
        "suspicious_payloads": [] # Stores MITRE T-Codes now
    }
    
    # 2. Define High-Risk Ports (Legacy Check)
    # The MITRE Engine will also check these via signatures, but this is a fast pre-filter
    suspicious_ports_map = {
        4444: "Metasploit Default",
        6667: "IRC Botnet",
        1337: "Elite/Backdoor",
        31337: "Back Orifice",
        23: "Telnet",
        3389: "RDP"
    }
    
    # 3. Analyze Packets
    for pkt in packets:
        # Protocol Stats & IP Tracking
        if IP in pkt:
            stats["ips"][pkt[IP].src] += 1
            stats["ips"][pkt[IP].dst] += 1
            
        if TCP in pkt:
            stats["protocols"]["TCP"] += 1
            # Check Port against list
            if pkt[TCP].dport in suspicious_ports_map:
                port_name = suspicious_ports_map[pkt[TCP].dport]
                # Map Port to MITRE ID
                tag = get_mitre_tag(str(pkt[TCP].dport), f"High Risk Port: {port_name}")
                stats["suspicious_ports"].append(tag)
                
        elif UDP in pkt:
            stats["protocols"]["UDP"] += 1

        # 4. Deep Packet Inspection (DPI) -> MITRE BRAIN SCAN
        # This scans the actual data inside the packet
        if pkt.haslayer(Raw):
            try:
                # Decode payload (ignore errors for binary data)
                payload = pkt[Raw].load.decode('utf-8', errors='ignore').lower()
                
                # 🔥 MITRE SCAN: Check payload against ALL 50+ Signatures
                # This finds: 'os.system', 'eval(', 'powershell', 'cmd.exe', etc. inside the network stream
                for signature in MITRE_SIGNATURES.keys():
                    if signature.lower() in payload:
                        # Map found signature to MITRE ID
                        tag = get_mitre_tag(signature, f"Payload Artifact: '{signature}'")
                        stats["suspicious_payloads"].append(tag)
                        
            except:
                pass

    # Deduplicate findings
    stats["suspicious_ports"] = list(set(stats["suspicious_ports"]))
    stats["suspicious_payloads"] = list(set(stats["suspicious_payloads"]))
   
    
    return stats
# from scapy.all import rdpcap, IP, TCP, UDP, Raw
# from io import BytesIO
# import collections

# # 🔥 CRITICAL FIX: Connect to the New MITRE Class Brain
# try:
#     from analyzer.mitre_mapping import MITRE_ENGINE
# except ImportError:
#     # Safe fallback if engine is missing during testing
#     MITRE_ENGINE = None

# def analyze_pcap(file_content):
#     """
#     Analyzes PCAP data for suspicious Ports AND suspicious Payloads (DPI).
#     Scans every packet against the MITRE Matrix for 50+ threats.
#     """
#     # 1. Setup Scapy
#     pcap_file = BytesIO(file_content)
#     try:
#         packets = rdpcap(pcap_file)
#     except Exception as e:
#         return {
#             "packet_count": 0,
#             "protocols": {},
#             "suspicious_ports": [],
#             "suspicious_payloads": [f"Error parsing PCAP: {str(e)}"]
#         }
    
#     stats = {
#         "packet_count": len(packets),
#         "protocols": collections.Counter(),
#         "ips": collections.Counter(),
#         "suspicious_ports": [],
#         "suspicious_payloads": [] # Stores MITRE T-Codes now
#     }
    
#     # 2. Define High-Risk Ports (Fast Pre-filter)
#     # These map to specific axes on your Radar Chart
#     suspicious_ports_map = {
#         4444: "Metasploit Default",   # -> [T1095] C2
#         6667: "IRC Botnet",           # -> [T1071] C2
#         1337: "Elite/Backdoor",       # -> [T1095] C2
#         31337: "Back Orifice",        # -> [T1095] C2
#         23: "Telnet (Insecure)",      # -> [T1095] Recon
#         3389: "RDP (Lateral Mov)",    # -> [T1021] Lateral Movement
#         53: "DNS (Tunneling Risk)",   # -> [T1071] Exfiltration
#         21: "FTP (Cleartext)"         # -> [T1048] Exfiltration
#     }
    
#     # 3. Analyze Packets
#     for pkt in packets:
#         # Protocol Stats & IP Tracking
#         if IP in pkt:
#             stats["ips"][pkt[IP].src] += 1
#             stats["ips"][pkt[IP].dst] += 1
            
#         if TCP in pkt:
#             stats["protocols"]["TCP"] += 1
#             # Check Port against list
#             if pkt[TCP].dport in suspicious_ports_map:
#                 port_name = suspicious_ports_map[pkt[TCP].dport]
                
#                 # Assign MITRE Tags based on Port Type for Radar Chart
#                 t_code = "T1095" # Default: Non-Standard Port
#                 if pkt[TCP].dport in [3389]: t_code = "T1021" # Remote Services
#                 if pkt[TCP].dport in [53, 21]: t_code = "T1048" # Exfiltration
                
#                 tag = f"[{t_code}] High Risk Port: {port_name} ({pkt[TCP].dport})"
#                 stats["suspicious_ports"].append(tag)
                
#         elif UDP in pkt:
#             stats["protocols"]["UDP"] += 1

#         # 4. Deep Packet Inspection (DPI) -> MITRE BRAIN SCAN
#         # This scans the actual data inside the packet
#         if pkt.haslayer(Raw) and MITRE_ENGINE:
#             try:
#                 # Decode payload (ignore errors for binary data)
#                 payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                
#                 # 🔥 MITRE SCAN: Check payload using the Class-based Engine
#                 # This finds: 'os.system', 'eval(', 'powershell', 'cmd.exe', etc. inside the network stream
#                 findings = MITRE_ENGINE.scan(payload)
                
#                 for f in findings:
#                     # f is a dict: {'id': 'T1059', 'name': '...', 'severity': '...'}
#                     # We format this so the Risk Engine (utils.py) can pick it up
#                     tag = f"[{f['id']}] Network Artifact: {f['name']}"
#                     stats["suspicious_payloads"].append(tag)
                        
#             except Exception:
#                 pass

#     # Deduplicate findings to keep the report clean
#     stats["suspicious_ports"] = list(set(stats["suspicious_ports"]))
#     stats["suspicious_payloads"] = list(set(stats["suspicious_payloads"]))
    
#     return stats