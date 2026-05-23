from tkinter import ttk


def create_table(root):
    table = ttk.Treeview(root)
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
