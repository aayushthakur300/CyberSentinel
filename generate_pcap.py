from scapy.all import wrpcap, Ether, IP, TCP, Raw

# 1. Create a packet simulating a Metasploit connection (Port 4444)
# This should trigger: "NETWORK: Suspicious traffic on Port 4444"
pkt1 = Ether() / IP(src="192.168.1.100", dst="10.0.0.5") / TCP(dport=4444) / Raw(load="Metasploit connection init")

# 2. Create a packet with a Cleartext Password
# This should trigger: "DATA THEFT: Potential cleartext credentials found"
pkt2 = Ether() / IP(src="192.168.1.100", dst="10.0.0.5") / TCP(dport=80) / Raw(load="POST /login HTTP/1.1\r\nHost: bank.com\r\n\r\nuser=admin&password=SecretPassword123!")

# 3. Create a packet simulating Telnet (Port 23)
pkt3 = Ether() / IP(src="192.168.1.100", dst="10.0.0.5") / TCP(dport=23) / Raw(load="Telnet login prompt")

print("[+] Generating 'test_threat.pcap'...")
wrpcap("test_threat.pcap", [pkt1, pkt2, pkt3])
print("[+] Done! Upload 'test_threat.pcap' to your analyzer.")