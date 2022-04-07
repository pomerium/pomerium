#!/usr/bin/env python3
import os.path
import uuid
from typing import Any, IO
from ruamel.yaml import YAML

yaml = YAML()


def main():
    d = os.path.join(os.path.dirname(__file__),
                     "..", "docs", "reference")
    d = os.path.normpath(d)
    print(f"generating {d}/readme.md")

    settings_path = f"{d}/settings.yaml"

    enterprise_settings_path = os.path.normpath(os.path.join(os.path.dirname(__file__), '..',
                                                             'docs', 'enterprise', 'console-settings.yaml'))

    rewrite_settings_yaml(settings_path)
    rewrite_settings_yaml(enterprise_settings_path)

    with open(settings_path) as f:
        doc = yaml.load(f)

    f = open(os.path.join(os.path.dirname(__file__),
                          "..", "docs", "reference", "readme.md"), "w")
    f.write(f"{doc['preamble']}\n")
    write_setting(f, 1, doc)
    f.write(f"{doc['postamble']}")
    f.close()


def rewrite_settings_yaml(path):
    path = os.path.normpath(os.path.join(os.path.dirname(__file__), '..',
                                         'docs', 'enterprise', 'console-settings.yaml'))

    with open(path) as f:
        doc = yaml.load(f)

    add_uuid(doc['settings'])

    with open(path, 'w') as f:
        yaml.dump(doc, f)


def add_uuid(settings):
    for setting in settings:
        if not 'uuid' in setting:
            setting['uuid'] = str(uuid.uuid4())

        if 'settings' in setting:
            add_uuid(setting['settings'])


def write_setting(w, depth, setting):
    if 'name' in setting:
        w.write(f"{'#' * depth} {setting.get('name', '')}\n")

    if 'attributes' in setting:
        w.write(f"{setting.get('attributes','')}\n")

    if 'doc' in setting:
        w.write(f"{setting.get('doc', '')}\n")

    w.write("\n")

    for subsetting in setting.get('settings', []):
        write_setting(w, depth+1, subsetting)


if __name__ == "__main__":
    main()
