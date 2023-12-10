from .models import *
from pathlib import Path
import json


def load_target_file(targetfile):
    with open(targetfile, "r") as fh:
        targets = json.load(fh)
        return Targets(**targets)


def find_target_files(basedir):
    target_files = Path(basedir).glob("*/target.json")
    for t in target_files:
        print(f"Found {t}")
        targets = load_target_file(t)
        print(f"targets: {targets}")
