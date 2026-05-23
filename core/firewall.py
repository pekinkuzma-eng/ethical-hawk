import subprocess
import shutil

blocked_ips = set()


def block_ip(ip):
    if ip in blocked_ips:
        return
    
    # Проверяем, существует ли iptables
    if not shutil.which("iptables"):
        print(f"[FIREWALL] iptables not installed, skipping block for {ip}")
        return
    
    try:
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )
        blocked_ips.add(ip)
        print(f"[FIREWALL] IP blocked: {ip}")
    except Exception as error:
        print(f"Firewall error: {error}")
