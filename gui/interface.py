import threading
import tkinter as tk
from tkinter import ttk

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

        self.table = self.create_table()

    def create_table(self):
        table = ttk.Treeview(self.root)
        table["columns"] = ("ID", "Time", "IP", "Type", "Status")
        
        table.column("#0", width=0, stretch=False)
        table.column("ID", width=50)
        table.column("Time", width=180)
        table.column("IP", width=120)
        table.column("Type", width=150)
        table.column("Status", width=100)
        
        table.heading("ID", text="ID")
        table.heading("Time", text="Time")
        table.heading("IP", text="IP")
        table.heading("Type", text="Attack Type")
        table.heading("Status", text="Status")
        
        table.pack(fill="both", expand=True)
        return table

    def start_monitoring(self):
        self.status_label.config(text="System Status: RUNNING", fg="green")
        sniff_thread = threading.Thread(target=sniffer.start, daemon=True)
        sniff_thread.start()

    def load_attacks(self):
        for row in self.table.get_children():
            self.table.delete(row)
        
        attacks = database.get_attacks()
        for attack in attacks:
            self.table.insert("", "end", values=(
                attack[0], attack[1], attack[2], attack[3], attack[5]
            ))

    def run(self):
        self.root.mainloop()


def start_gui():
    app = EthicalHawkGUI()
    app.run()

