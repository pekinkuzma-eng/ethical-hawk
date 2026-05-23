import os

# Создаем папки при запуске
os.makedirs("logs", exist_ok=True)
os.makedirs("database", exist_ok=True)

from gui.interface import start_gui

if __name__ == "__main__":
    start_gui()
from gui.interface import start_gui

if __name__ == "__main__":
    start_gui()
