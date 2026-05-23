import os
import sqlite3
from config import DATABASE_PATH


class Database:

    def __init__(self):
        self.connection = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        self.cursor = self.connection.cursor()
        self.create_table()

    def create_table(self):
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                ip TEXT,
                attack_type TEXT,
                payload TEXT,
                status TEXT
            )
            """
        )
        self.connection.commit()

    def save_attack(self, timestamp, ip, attack_type, payload, status):
        self.cursor.execute(
            """
            INSERT INTO attacks (
                timestamp,
                ip,
                attack_type,
                payload,
                status
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (timestamp, ip, attack_type, payload, status)
        )

        self.connection.commit()

    def get_attacks(self):
        self.cursor.execute("SELECT * FROM attacks")
        return self.cursor.fetchall()
