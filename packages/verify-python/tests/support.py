"""Shared test setup: import the package from src/ without installing it, and load the vectors."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PACKAGE_ROOT = os.path.dirname(HERE)
REPO_ROOT = os.path.dirname(os.path.dirname(PACKAGE_ROOT))
SRC = os.path.join(PACKAGE_ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)


def load_vectors(name):
    with open(os.path.join(REPO_ROOT, "spec", "vectors", name), encoding="utf-8") as handle:
        return json.load(handle)
