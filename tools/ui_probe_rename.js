/* Probe: renaming a picture in the web UI, and the notes that showed it follow the new name. */
async function (lines, log, until, sleep) {
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  // The note's own text is what matters, and the rendered image is a blob: URL — read the file.
  async function noteText(path) {
    const response = await fetch("/api/call", {
      method: "POST",
      headers: {
        "X-Vault-Token": window.sessionStorage.getItem("vault_token") || "",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ method: "vault.read_file", params: { path: path } })
    });
    const data = await response.json();
    return (data.result && data.result.content) || "";
  }

  const target = "/الف/ب/ج/ادیتور.md";
  const before = await noteText(target);
  log(before.indexOf("dot.png") >= 0, "the note references the picture before the rename",
      before.split("\n").filter((l) => l.indexOf("dot.png") >= 0)[0] || "");

  // rename dot.png from its row (the ✏️ action opens the shared modal)
  location.hash = "#/folder/" + encodeURIComponent("attachments");
  const row = await until(
    () => $$("#notes-list li").find((li) => li.textContent.indexOf("dot.png") >= 0),
    "the picture row"
  );
  if (!row) { return; }
  const rename = row.querySelector('button.row-action[title="تغییر نام"]');
  log(!!rename, "the row carries a rename action");
  if (!rename) { return; }
  rename.click();
  const input = await until(() => $("#modal-root input[type=text]"), "rename dialog");
  if (!input) { return; }
  log(input.value === "dot.png", "the dialog starts from the current name", input.value);
  input.value = "dot-renamed.png";
  input.dispatchEvent(new Event("input", { bubbles: true }));
  const ok = $$("#modal-root button").find((b) => b.textContent.trim() === "ذخیره");
  log(!!ok, "the dialog has its save button");
  if (!ok) { return; }
  ok.click();

  const toast = await until(() => {
    const text = ($("#toast-root") || {}).textContent || "";
    return text.indexOf("سند") >= 0 ? text : null;
  }, "reference toast");
  log(!!toast, "the result says how many documents were repointed", (toast || "").slice(0, 80));

  const listing = await until(
    () => $$("#notes-list li").find((li) => li.textContent.indexOf("dot-renamed.png") >= 0),
    "the renamed row"
  );
  log(!!listing, "the list shows the new name");

  const after = await noteText(target);
  log(after.indexOf("dot-renamed.png") >= 0, "the note was rewritten to the new name");
  log(after.indexOf("/attachments/dot.png") < 0, "no stale reference is left behind");

  // and the rewritten note still shows a picture
  location.hash = "#/note/" + encodeURIComponent(target);
  await until(() => !!$("#note-body img"), "the picture in the note");
  const img = $("#note-body img");
  await until(() => img.complete, "image load");
  log(img.naturalWidth > 0, "the picture still loads in the rewritten note",
      img.naturalWidth + "x" + img.naturalHeight);
}
