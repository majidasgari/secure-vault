#!/usr/bin/env python3
"""CDP driver for the Secure Vault SPA: unlock, then run a JS test file in the page.

Usage: cdp_probe.py <app-url> <password> [screenshot.png] [test.js]
Without test.js the built-in UI test runs.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from websockets.sync.client import connect

PRELUDE = r"""
(async () => {
  const lines = [];
  const log = (ok, name, extra) => lines.push((ok ? "PASS" : "FAIL") + " | " + name + (extra ? " | " + extra : ""));
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  async function until(fn, label, tries) {
    for (let i = 0; i < (tries || 40); i++) {
      let v = null;
      try { v = fn(); } catch (err) { v = null; }
      if (v) { return v; }
      await sleep(300);
    }
    log(false, "timeout waiting for " + label);
    return null;
  }
  window.__log = log;
  window.__until = until;
  window.__sleep = sleep;
  const pw = await until(() => document.getElementById("password-input"), "login form");
  if (!pw) { return lines; }
  pw.value = "__PW__";
  document.getElementById("login-form").dispatchEvent(new Event("submit", {bubbles: true, cancelable: true}));
  await until(() => document.getElementById("app-view") && !document.getElementById("app-view").hidden, "app view");
  const ok = !!(document.getElementById("app-view") && !document.getElementById("app-view").hidden);
  log(ok, "app view visible");

  if (ok && window.__TEST__) {
    await window.__TEST__(lines, log, until, sleep);
  } else if (ok) {
    // built-in UI test: breadcrumbs, folder creation, new note
    const crumbs = (sel) => Array.from(document.querySelectorAll(sel + " button")).map((b) => b.textContent.trim());
    log(!!document.getElementById("btn-new-note-side"), "new-note button present (sidebar)");
    log(!!document.getElementById("btn-new-folder"), "new-folder button present");
    location.hash = "#/folder/" + encodeURI("الف/ب/ج");
    await until(() => document.querySelectorAll("#folder-crumbs button").length >= 3, "deep crumbs");
    log(true, "crumbs", crumbs("#folder-crumbs").join(" > "));
    const total = document.querySelectorAll("#folder-crumbs button").length;
    for (let i = 0; i < total; i++) {
      const before = crumbs("#folder-crumbs").join(" > ");
      const btn = document.querySelectorAll("#folder-crumbs button")[i];
      if (!btn) { log(false, "crumb " + i + " rendered"); continue; }
      const label = btn.textContent.trim();
      const isLast = i === total - 1;
      btn.click();
      await until(() => crumbs("#folder-crumbs").join(" > ") !== before, "crumb nav", 6);
      await sleep(200);
      const after = crumbs("#folder-crumbs").join(" > ");
      if (isLast) {
        // the current folder is marked, not clickable
        log(after === before && btn.getAttribute("aria-current") === "page" && btn.disabled,
            "crumb " + i + " (" + label + ") is the current one", before + "  =>  " + after);
      } else {
        log(after !== before, "crumb " + i + " (" + label + ") clickable", before + "  =>  " + after);
      }
      if (after !== before) {
        location.hash = "#/folder/" + encodeURI("الف/ب/ج");
        await until(() => crumbs("#folder-crumbs").join(" > ").indexOf("ج") >= 0, "back to deep", 10);
      }
    }
    const fbtn = document.getElementById("btn-new-folder");
    if (fbtn) {
      location.hash = "#/folder/" + encodeURI("الف/ب");
      // wait for the *exact* crumb trail: "ب" alone also matches the deeper folder we came from
      await until(() => crumbs("#folder-crumbs").join(">") === "ریشه>الف>ب", "on folder ب", 25);
      fbtn.click();
      const input = await until(() => document.querySelector("#modal-root input[type=text]"), "folder dialog");
      if (input) {
        input.value = "زیرپوشه";
        input.dispatchEvent(new Event("input", {bubbles: true}));
        const okb = document.querySelector("#modal-root .actions button.primary") ||
                    document.querySelector("#modal-root button.primary");
        if (okb) {
          okb.click();
          await sleep(2500);
          const seen = await until(() => Array.from(document.querySelectorAll("#notebook-list span"))
            .some((s) => s.textContent.indexOf("زیرپوشه") >= 0), "new folder row", 25);
        log(true, "toast (folder)", (document.querySelector("#toast-root").textContent || "(none)").slice(0, 80));
          const names = Array.from(document.querySelectorAll("#notebook-list span")).map((s) => s.textContent.trim());
          log(!!seen, "subfolder appears in the list", names.join(" | ").slice(0, 140));
        } else { log(false, "folder dialog has a create button"); }
      }
    }
    const nbtn = document.getElementById("btn-new-note-side") || document.getElementById("btn-new-note");
    if (nbtn) {
      nbtn.click();
      const input = await until(() => document.querySelector("#modal-root input[type=text]"), "note dialog");
      if (input) {
        input.value = "یادداشت تازه";
        input.dispatchEvent(new Event("input", {bubbles: true}));
        const okb = document.querySelector("#modal-root .actions button.primary") ||
                    document.querySelector("#modal-root button.primary");
        if (okb) { okb.click(); }
        await until(() => document.getElementById("view-edit") && !document.getElementById("view-edit").hidden, "editor", 15);
        const editor = document.getElementById("editor");
        const open = !!(document.getElementById("view-edit") && !document.getElementById("view-edit").hidden);
        log(open, "editor opened for the new note", open ? document.getElementById("editor-path").textContent : "");
        log(!!editor && editor.value.length > 0, "seed content present", editor ? JSON.stringify(editor.value.slice(0, 30)) : "");
      }
    }
  }
  return lines;
})()
"""


def main() -> None:
    """Launch Chrome, evaluate the test, print the verdicts, optionally screenshot."""
    url, password = sys.argv[1], sys.argv[2]
    shot = Path(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] != "-" else None
    test_file = Path(sys.argv[4]) if len(sys.argv) > 4 else None
    port = 9333
    chrome = subprocess.Popen(  # noqa: S603
        [
            "google-chrome-stable", "--headless=new", "--no-sandbox", "--disable-gpu",
            "--disable-dev-shm-usage", f"--remote-debugging-port={port}",
            "--user-data-dir=/tmp/cdp-profile-secure-vault", "--window-size=" + os.environ.get("PROBE_W", "1500") + "," + os.environ.get("PROBE_H", "950"), "about:blank",
        ],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        target = ""
        for _ in range(40):
            time.sleep(0.5)
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=2) as r:  # noqa: S310
                    for page in json.loads(r.read()):
                        if page.get("type") == "page":
                            target = page["webSocketDebuggerUrl"]
                            break
                if target:
                    break
            except Exception:  # noqa: BLE001 - chrome still starting
                continue
        if not target:
            print("could not reach the debugging endpoint")
            return

        with connect(target, max_size=64 * 1024 * 1024) as ws:
            counter = {"id": 0}

            def send(method: str, **params) -> dict:
                counter["id"] += 1
                mid = counter["id"]
                ws.send(json.dumps({"id": mid, "method": method, "params": params}))
                while True:
                    message = json.loads(ws.recv(timeout=180))
                    if message.get("id") == mid:
                        return message

            send("Page.enable")
            send("Runtime.enable")
            width = int(os.environ.get("PROBE_W", "1500"))
            height = int(os.environ.get("PROBE_H", "950"))
            send("Emulation.setDeviceMetricsOverride", width=width, height=height,
                 deviceScaleFactor=1, mobile=width < 800)
            send("Page.navigate", url=url)
            time.sleep(3)
            source = PRELUDE.replace("__PW__", password)
            if test_file:
                source = "window.__TEST__ = " + test_file.read_text(encoding="utf-8") + ";\n" + source
            result = send(
                "Runtime.evaluate", expression=source, awaitPromise=True, returnByValue=True,
            )
            value = result.get("result", {}).get("result", {}).get("value")
            if value is None:
                print("no verdicts:", json.dumps(result)[:500])
            elif isinstance(value, list):
                for line in value:
                    print(line)
            else:
                payload = result.get("result", {})
                details = payload.get("exceptionDetails") or payload.get("result", {}).get("description")
                print(json.dumps(value, ensure_ascii=False)[:600])
                if details:
                    print("EXCEPTION:", json.dumps(details, ensure_ascii=False)[:900])
            if shot:
                time.sleep(1)
                data = send("Page.captureScreenshot", format="png")
                shot.write_bytes(base64.b64decode(data["result"]["data"]))
                print(f"screenshot: {shot}")
    finally:
        chrome.terminate()


if __name__ == "__main__":
    main()
