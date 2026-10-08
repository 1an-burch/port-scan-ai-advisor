import socket
import ollama

target_ip = "10.89.3.59"
ports_to_scan = [21, 22, 80]
found_ports = []

PORT_INFO = {
    21: {
        "service": "FTP",
        "risk": "Unencrypted credentials and file transfer; often misconfigured for anonymous access.",
        "commands": [
            "sudo ufw deny 21          # block the port if FTP isn't needed",
            "sudo systemctl disable --now vsftpd   # or whatever FTP daemon is running",
        ],
    },
    22: {
        "service": "SSH",
        "risk": "Common brute-force target; root login or weak host key algorithms increase risk.",
        "commands": [
            "sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
            "sudo systemctl restart sshd",
            "# Consider: key-based auth only, fail2ban, non-default port",
        ],
    },
    80: {
        "service": "HTTP",
        "risk": "Unencrypted web traffic; vulnerable to interception and common web app exploits.",
        "commands": [
            "sudo ufw deny 80          # if the service isn't meant to be public",
            "# Consider: redirect to HTTPS (443) with a valid TLS cert instead of blocking",
        ],
    },
}

FALLBACK_SUMMARY = "Open port increases attack surface; review whether the service needs to be exposed."


def scan_ports(ip, ports):
    open_ports = []
    print(f"[*] Starting local scan against {ip}...")
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        result = s.connect_ex((ip, port))
        if result == 0:
            print(f"[+] Found Open Port: {port}")
            open_ports.append(port)
        s.close()
    return open_ports


def get_ai_summary(port, service, risk):
    """Ask Ollama for a short plain-English explanation. Advisory only --
    output is never parsed into commands or executed."""
    prompt = f"""You are a defensive security advisor. In 2-3 short sentences,
explain to a junior sysadmin why leaving port {port} ({service}) open is a risk,
and what general precaution they should consider.
Base risk info: {risk}
Respond in plain text only -- no markdown, no lists, no JSON."""

    try:
        response = ollama.generate(model="llama3", prompt=prompt)
        text = response["response"].strip()
        return text if text else FALLBACK_SUMMARY
    except Exception as e:
        print(f"[!] Ollama unavailable for port {port} ({e}), using fallback summary.")
        return FALLBACK_SUMMARY


def print_checklist(found_ports):
    print("\n" + "=" * 60)
    print("  DEFENSIVE SECURITY CHECKLIST  ")
    print("=" * 60)

    for port in found_ports:
        info = PORT_INFO.get(port)
        if not info:
            print(f"\n[Port {port}] No reference info available for this port.")
            continue

        summary = get_ai_summary(port, info["service"], info["risk"])

        print(f"\n[Port {port}] {info['service']}")
        print(f"  Risk:    {info['risk']}")
        print(f"  AI note: {summary}")
        print(f"  Suggested commands (run manually, review before executing):")
        for cmd in info["commands"]:
            print(f"    $ {cmd}")

    print("\n" + "=" * 60)
    print("  Nothing above was executed automatically.")
    print("  Copy/review each command yourself before running it on the target.")
    print("=" * 60)


def main():
    found_ports = scan_ports(target_ip, ports_to_scan)

    if not found_ports:
        print("[-] No open ports discovered during initial sweep.")
        return

    print_checklist(found_ports)


if __name__ == "__main__":
    main()