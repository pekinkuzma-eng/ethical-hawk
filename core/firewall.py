import subprocess


blocked_ips = set()


def block_ip(ip):

    if ip in blocked_ips:
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
