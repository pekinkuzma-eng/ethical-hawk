import threading
import tkinter as tk

from gui.dashboard import create_table

from core.sniffer import Sniffer
from core.database import Database


sniffer = Sniffer()
database = Database()


class EthicalHawkGUI:

    def __init__(self):

        self.root = tk.Tk()

        self.root.title("Ethical Hawk IDS/IPS")
        self.root.geometry("900x500")

        self.status_label = tk.Label(
            self.root,
            text="System Status: STOPPED",
            fg="red",
            font=("Arial", 12, "bold")
        )

        self.status_label.pack(pady=10)

        self.start_button = tk.Button(
            self.root,
            text="Start Monitoring",
            command=self.start_monitoring,
            bg="green",
            fg="white",
            width=20
        )

        self.start_button.pack(pady=5)

        self.refresh_button = tk.Button(
            self.root,
            text="Refresh Logs",
            command=self.load_attacks,
            bg="blue",
            fg="white",
            width=20
        )

        self.refresh_button.pack(pady=5)

        self.table = create_table(self.root)

    def start_monitoring(self):

        self.status_label.config(
            text="System Status: RUNNING",
            fg="green"
        )

        sniff_thread = threading.Thread(
            target=sniffer.start,
            daemon=True
        )

        sniff_thread.start()

    def load_attacks(self):

        for row in self.table.get_children():
            self.table.delete(row)

        attacks = database.get_attacks()

        for attack in attacks:
            self.table.insert(
                "",
                "end",
                values=(
                    attack[0],
                    attack[1],
                    attack[2],
                    attack[3],
                    attack[5]
                )
            )

    def run(self):
        self.root.mainloop()


def start_gui():
    app = EthicalHawkGUI()
    app.run()
