#!/usr/bin/env python3
"""Export a KeePassXC (.kdbx) database to JSON without leaking values to stdout.

Usage:
    KP_PW_FILE=~/.keepass.pw extract.py <db.kdbx> [--out DIR] [--summary]

Runs `keepassxc-cli export -f xml` with the master password fed on stdin (read
from KP_PW_FILE, never printed), parses the KeePass XML into a list of entries and
writes <out>/entries.json (0600).  Only non-secret metadata is printed: counts and
entry TITLES (never usernames, passwords, URLs or notes).

Work dir defaults to a tmpfs path (/run/user/1000/kp-migration) so the plaintext
XML never lands on a spinning disk.
"""
from __future__ import annotations

import base64
import gzip
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

DEFAULT_OUT = Path("/run/user/1000/kp-migration")
STANDARD_KEYS = ("Title", "UserName", "Password", "URL", "Notes")


def master_password() -> str:
    """Read the master password from KP_PW_FILE (default ~/.keepass.pw)."""
    path = Path(os.environ.get("KP_PW_FILE", "~/.keepass.pw")).expanduser()
    if not path.exists():
        sys.exit(f"password file not found: {path} (set KP_PW_FILE)")
    return path.read_text(encoding="utf-8").rstrip("\n")


def key_file(argv: list[str]) -> Path | None:
    """Return the DB key file from --key-file or KP_KEY_FILE (None when unused)."""
    raw = ""
    if "--key-file" in argv:
        raw = argv[argv.index("--key-file") + 1]
    else:
        raw = os.environ.get("KP_KEY_FILE", "")
    if not raw:
        return None
    path = Path(raw).expanduser()
    if not path.exists():
        sys.exit(f"key file not found: {path}")
    return path


def export_xml(db: Path, out_xml: Path, password: str, keyfile: Path | None = None) -> None:
    """Run keepassxc-cli export and store the XML at out_xml (mode 0600)."""
    cmd = ["keepassxc-cli", "export", "-q", "-f", "xml"]
    if keyfile is not None:
        cmd += ["-k", str(keyfile)]
    cmd.append(str(db))
    proc = subprocess.run(cmd, input=password + "\n", capture_output=True, text=True)
    if proc.returncode != 0 or not proc.stdout.lstrip().startswith("<?xml"):
        msg = (proc.stderr or proc.stdout).strip().splitlines()
        raise SystemExit(f"export failed: {msg[:3]}")
    out_xml.write_text(proc.stdout, encoding="utf-8")
    out_xml.chmod(0o600)


def _text(node: ET.Element | None) -> str:
    return "" if node is None else (node.text or "")


def parse_groups(root_el: ET.Element, binaries: dict[str, bytes]) -> list[dict]:
    """Walk <Root><Group>… collecting entries with their group path."""
    entries: list[dict] = []

    def walk(group: ET.Element, parents: list[str]) -> None:
        name = _text(group.find("Name")).strip()
        path = parents + ([name] if name else [])
        for entry in group.findall("Entry"):
            entries.append(parse_entry(entry, path, binaries))
        for sub in group.findall("Group"):
            walk(sub, path)

    root_group = root_el.find("Root/Group")
    if root_group is None:
        raise SystemExit("no <Root><Group> in export")
    walk(root_group, [])
    return entries


def parse_entry(entry: ET.Element, group_path: list[str], binaries: dict[str, bytes]) -> dict:
    """Turn one <Entry> into a plain dict."""
    strings: dict[str, str] = {}
    protected: list[str] = []
    for string in entry.findall("String"):
        key = _text(string.find("Key"))
        value_el = string.find("Value")
        value = _text(value_el)
        if value_el is not None and value_el.get("Protected") == "True":
            protected.append(key)
        strings[key] = value
    custom = {k: v for k, v in strings.items() if k not in STANDARD_KEYS}
    attachments: list[dict] = []
    for binary in entry.findall("Binary"):
        ref = _text(binary.find("Value"))
        blob = binaries.get(ref)
        attachments.append(
            {
                "name": _text(binary.find("Key")),
                "ref": ref,
                "bytes": len(blob) if blob is not None else 0,
                "data_b64": base64.b64encode(blob).decode() if blob else "",
            }
        )
    times = entry.find("Times")
    return {
        "uuid": _text(entry.find("UUID")),
        "group_path": group_path,
        "title": strings.get("Title", "").strip(),
        "username": strings.get("UserName", ""),
        "password": strings.get("Password", ""),
        "url": strings.get("URL", ""),
        "notes": strings.get("Notes", ""),
        "custom": custom,
        "protected_keys": protected,
        "tags": [t.strip() for t in _text(entry.find("Tags")).split(";") if t.strip()],
        "expires": _text(times.find("Expires")) if times is not None else "",
        "expiry_time": _text(times.find("ExpiryTime")) if times is not None else "",
        "attachments": attachments,
    }


def load_binaries(root_el: ET.Element) -> dict[str, bytes]:
    """Decode <Meta><Binaries><Binary ID=…> blobs (gzip when Compressed)."""
    out: dict[str, bytes] = {}
    for binary in root_el.findall("Meta/Binaries/Binary"):
        raw = base64.b64decode((binary.text or "").strip() or "")
        if binary.get("Compressed") == "True" and raw:
            try:
                raw = gzip.decompress(raw)
            except OSError:
                pass
        out[binary.get("ID", "")] = raw
    return out


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        return int(bool(sys.stderr.write(__doc__ or "")))
    db = Path(argv[1]).expanduser()
    out_dir = DEFAULT_OUT
    if "--out" in argv:
        out_dir = Path(argv[argv.index("--out") + 1])
    out_dir.mkdir(parents=True, exist_ok=True)
    out_dir.chmod(0o700)

    xml_path = out_dir / (db.stem.replace(" ", "_") + ".xml")
    export_xml(db, xml_path, master_password(), key_file(argv))

    tree = ET.parse(xml_path)
    root_el = tree.getroot()
    binaries = load_binaries(root_el)
    entries = parse_groups(root_el, binaries)

    data = {
        "source_db": str(db),
        "db_name": _text(root_el.find("Meta/DatabaseName")),
        "entries": entries,
    }
    json_path = out_dir / "entries.json"
    json_path.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    json_path.chmod(0o600)

    groups: dict[str, int] = defaultdict(int)
    for e in entries:
        groups["/".join(e["group_path"]) or "(root)"] += 1
    print(f"db={db.name} entries={len(entries)} groups={len(groups)}")
    n_pw = sum(1 for e in entries if e["password"])
    n_user = sum(1 for e in entries if e["username"])
    n_url = sum(1 for e in entries if e["url"])
    n_note = sum(1 for e in entries if e["notes"])
    n_totp = sum(1 for e in entries if any("otp" in k.lower() for k in e["custom"]))
    n_att = sum(1 for e in entries if e["attachments"])
    n_custom = sum(1 for e in entries if e["custom"])
    print(
        f"pass_fields={n_pw} with_username={n_user} with_url={n_url} "
        f"with_notes={n_note} with_totp={n_totp} with_custom={n_custom} with_attachments={n_att}"
    )
    print("--- groups ---")
    for name, count in sorted(groups.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"{count:4d}  {name}")
    print(f"--- json: {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
