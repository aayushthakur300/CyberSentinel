from scapy.all import wrpcap, Ether, IP, TCP, Raw

# 1. Metasploit C2 Simulation (Port 4444)
pkt1 = Ether() / IP(dst="10.0.0.5") / TCP(dport=4444) / Raw(load="metasploit connection init")

# 2. Cleartext Data Theft (Port 80)
pkt2 = Ether() / IP(dst="10.0.0.5") / TCP(dport=80) / Raw(load="POST /login HTTP/1.1\r\nuser=admin&password=SecretPassword123!")

# 3. Suspicious Port (Port 31337)
pkt3 = Ether() / IP(dst="10.0.0.5") / TCP(dport=31337) / Raw(load="Elite Buffer Overflow Payload")

print("[+] Generating 'test_threat.pcap'...")
wrpcap("test_threat.pcap", [pkt1, pkt2, pkt3])
print("[+] Success! Upload this file to the 'Network' tab in CyberSentinel.")