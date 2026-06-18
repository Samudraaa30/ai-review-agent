import json
from pathlib import Path

FILE = "reviews.json"


def load_reviews():

    if not Path(FILE).exists():
        return []

    with open(FILE, "r") as f:
        return json.load(f)


def save_reviews(reviews):

    with open(FILE, "w") as f:
        json.dump(
            reviews,
            f,
            indent=4
        )