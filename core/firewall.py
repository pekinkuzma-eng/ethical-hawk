import subprocess
import shutil


class Firewall:

    @staticmethod
    def block_ip(ip):

        if not shutil.which("iptables"):

            print(
                "[WARNING] iptables not installed. "
                f"IP {ip} was not blocked."
            )

            return False

        try:

            subprocess.run(
                [
                    "sudo",
                    "iptables",
                    "-A",
                    "INPUT",
                    "-s",
                    ip,
                    "-j",
                    "DROP"
                ],
                check=True
            )

            print(f"[FIREWALL] IP blocked: {ip}")

            return True

        except Exception as error:

            print(f"[FIREWALL ERROR] {error}")

            return False
