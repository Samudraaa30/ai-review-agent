import json
from pathlib import Path

FILE = "users.json"

def load_users():

    if not Path(FILE).exists():
        return []

    with open(FILE,"r") as f:

        return json.load(f)

def save_users(users):

    with open(FILE,"w") as f:

        json.dump(
            users,
            f,
            indent=4
        )