/* Plain-Crepe A/B (SPEC/10 debugging): is the image problem Crepe's or this wrapper's?
 *
 * Needs `bunx vite --port 5310` running in tools/milkdown-editor:
 *   ./.venv/bin/python tools/ui_probe.py - tools/ui_probe_dev_plain.js
 */
async (lines, log, until, sleep) => {
  const mod = await import("http://127.0.0.1:5310/src/dev-probe.js")
    .catch((e) => ({ error: String(e && e.message) }));
  log(!!mod.mountPlain, "plain crepe entry imported", mod.error || "");
  if (!mod.mountPlain) { return lines; }

  const host = document.createElement("div");
  host.style.position = "fixed";
  host.style.left = "-10000px";
  host.style.width = "600px";
  document.body.appendChild(host);

  const doc = [
    "# plain",
    "",
    "![remote image](https://example.com/a.png)",
    "",
    "![relative](attachments/b.png)",
    "",
    "text with ![inline](https://example.com/c.png) inside",
    "",
    "| a | b |",
    "| --- | --- |",
    "| 1 | 2 |",
    ""
  ].join("\n");
  const crepe = await mod.mountPlain(host, doc);
  await sleep(1500);
  log(true, "plain markdown back", JSON.stringify(crepe.getMarkdown()).slice(0, 400));
  log(true, "plain blocks", Array.from(host.querySelectorAll(".ProseMirror > *")).map((b) =>
      b.tagName.toLowerCase() + "." + String(b.className).split(/\s+/)[0]).join(" | ").slice(0, 300));
  log(true, "plain imgs", Array.from(host.querySelectorAll("img")).map((e) =>
      JSON.stringify(String(e.getAttribute("src")).slice(0, 34))).join(" | ") || "(none)");
  log(true, "plain image components", Array.from(host.querySelectorAll("[class*=image]")).map((e) =>
      e.tagName + "." + String(e.className).split(/\s+/)[0]).join(" | ") || "(none)");
  await crepe.destroy();
  host.remove();
  return lines;
}
