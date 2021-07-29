#!/usr/bin/env python3
import os.path
from typing import Any, IO
import yaml


def main():
    d = os.path.join(os.path.dirname(__file__), "..", "docs", "enterprise")
    d = os.path.normpath(d)
    print(f"generating {d}/reference.md")

    f = open(os.path.join(d, "console-settings.yaml"))
    doc = yaml.full_load(f)
    f.close()

    f = open(
        os.path.join(
            os.path.dirname(__file__), "..", "docs", "enterprise", "reference.md"
        ),
        "w",
    )
    f.write(f"{doc['preamble']}\n")
    write_setting(f, 1, doc)
    f.write(f"{doc['postamble']}")
    f.close()


def write_setting(w, depth, setting):
    if "name" in setting:
        w.write(f"{'#' * depth} {setting.get('name', '')}\n")

    if "attributes" in setting:
        w.write(f"{setting.get('attributes','')}\n")

    if "doc" in setting:
        w.write(f"{setting.get('doc', '')}\n")

    w.write("\n")

    for subsetting in setting.get("settings", []):
        write_setting(w, depth + 1, subsetting)


if __name__ == "__main__":
    main()
