import re
import time

from collections import defaultdict

from core.logger import log_attack
from core.database import Database
from core.firewall import Firewall


request_counter = defaultdict(list)


class Detector:

    def __init__(self):

        self.database = Database()

        self.sql_patterns = [
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
            r"(\bOR\b|\bAND\b).*(=)",
            r"UNION\s+SELECT",
            r"DROP\s+TABLE",
            r"INSERT\s+INTO",
            r"SELECT\s+\*"
        ]

        self.xss_patterns = [
            r"<script>",
            r"</script>",
            r"alert\(",
            r"onerror=",
            r"javascript:"
        ]

    def detect_sql_injection(self, payload):

        for pattern in self.sql_patterns:

            if re.search(
                pattern,
                payload,
                re.IGNORECASE
            ):

                return True

        return False

    def detect_xss(self, payload):

        for pattern in self.xss_patterns:

            if re.search(
                pattern,
                payload,
                re.IGNORECASE
            ):

                return True

        return False

    def detect_bruteforce(self, ip):

        current_time = time.time()

        request_counter[ip].append(current_time)

        request_counter[ip] = [

            timestamp

            for timestamp in request_counter[ip]

            if current_time - timestamp < 10
        ]

        if len(request_counter[ip]) > 20:

            return True

        return False

    def process_attack(
        self,
        ip,
        payload,
        attack_type
    ):

        Firewall.block_ip(ip)

        message = (
            f"[{attack_type}] "
            f"IP={ip} "
            f"PAYLOAD={payload} "
            f"STATUS=BLOCKED"
        )

        log_attack(message)

        self.database.insert_attack(
            ip,
            attack_type,
            payload,
            "BLOCKED"
        )
