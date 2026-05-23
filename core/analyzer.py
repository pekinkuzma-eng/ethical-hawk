from collections import Counter

from core.database import Database


database = Database()


class Analyzer:

    def get_statistics(self):

        attacks = database.get_attacks()

        attack_types = [attack[3] for attack in attacks]

        return Counter(attack_types)
