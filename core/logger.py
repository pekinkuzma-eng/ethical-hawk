import logging
import os
from config import LOG_FILE

# Создаем папку для логов, если её нет
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)


def log_attack(message):
    logging.info(message)
    print(message)
