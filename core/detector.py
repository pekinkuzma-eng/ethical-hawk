import json
from collections import defaultdict

from core.firewall import block_ip
from core.logger import log_attack
from core.utils import get_timestamp
from core.database import Database

from config import BLOCK_SUSPICIOUS_IP
from config import MAX_REQUESTS_PER_MINUTE


with open("rules/signatures.json", "r") as file:
    signatures = json.load(file)


request_counter = defaultdict(int)

database = Database()


class Detector:

    def detect_sql_injection(self, payload):

        for signature in signatures["sql_injection"]:
            if signature.lower() in payload.lower():
                return True

        return False

    def detect_xss(self, payload):

        for signature in signatures["xss"]:
            if signature.lower() in payload.lower():
                return True

        return False

    def detect_bruteforce(self, ip):

        request_counter[ip] += 1

        if request_counter[ip] > MAX_REQUESTS_PER_MINUTE:
            return True

        return False

    def process_attack(self, ip, payload, attack_type):

        timestamp = get_timestamp()

        status = "DETECTED"

        if BLOCK_SUSPICIOUS_IP:
            block_ip(ip)
            status = "BLOCKED"

        message = (
            f"[{attack_type}] IP={ip} PAYLOAD={payload} STATUS={status}"
        )

        log_attack(message)

        database.save_attack(
            timestamp,
            ip,
            attack_type,
            payload,
            status
        )
