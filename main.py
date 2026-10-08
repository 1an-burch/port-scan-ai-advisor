import socket
import ollama

target_ip = "192.168.247.131"
ports_to_scan = [21, 22, 80]
found_ports = []

print(f"[*] Starting local scan against {target_ip}...")

for port in ports_to_scan:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    result = s.connect_ex((target_ip, port))
    if result == 0:
        print(f"[+] Found Open Port: {port}")
        found_ports.append(port)
    s.close()

if found_ports:
    scan_summary = f"The host {target_ip} has the following ports wide open: {found_ports}."

    prompt = f"""
    You are an automated defensive security analyst. 
    Review these raw scan results: {scan_summary}
    Provide a clear breakdown covering:
    1. What common vulnerabilities or risks are associated with these open ports?
    2. What specific defensive steps (like firewall rules or configuration changes) can close or secure them?
    Keep your response concise and focused on remediation.
    """

    print("\n[*] Sending results to local Llama 3 model for analysis...")

    response = ollama.generate(model='llama3', prompt=prompt)

    print("\n=== AI Security Analysis ===")
    print(response['response'])
else:
    print("[-] No open ports discovered during initial sweep.")