import logging
import os

from config import LOG_FILE


os.makedirs("logs", exist_ok=True)


logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)


def log_attack(message):
    logging.info(message)
    print(message)
