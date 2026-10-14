/* Page-side half of tools/secret_flow_probe.py — runs inside the real SPA over CDP.
 *
 * The driver hands us (lines, log, until, sleep) from its prelude. The Python side is a real
 * Secure Vault application in offscreen mode, and a watcher thread presses the permission
 * dialog's own button the way the user would — so what is asserted here is the behaviour Max
 * asked for, not a test-only shortcut.
 */
async (lines, log, until, sleep) => {
  const q = (sel) => document.querySelector(sel);
  const qa = (sel) => Array.from(document.querySelectorAll(sel));
  const folderHash = "#/folder/" + encodeURI("/رمزها/نمونه");

  // ---------------------------------------------------------------- the listing
  location.hash = folderHash;
  const rowFor = (name) => qa("#notes-list li").filter((li) => li.textContent.indexOf(name) >= 0)[0] || null;
  let row = await until(() => rowFor("card.md"), "the secret row", 40);
  log(!!row, "the secret entry is listed in the folder view");
  const actions = row ? row.querySelectorAll(".row-actions .row-action") : [];
  log(actions.length === 2, "the row offers rename + delete", actions.length + " buttons");

  // ------------------------------------------- 1. opening it asks the desktop app
  row.click();
  const pre = await until(() => q("#modal-root .modal pre.plain"), "the plain-text modal", 80);
  const text = pre ? pre.textContent : "";
  log(!!pre, "the approved text opened *here* in the browser");
  log(text.indexOf("SECRET-BODY-MARKER") >= 0, "the modal carries the file's own body",
      JSON.stringify(text.slice(0, 60)));
  log(!q("#note-body") || q("#note-body").textContent.indexOf("SECRET-BODY-MARKER") === -1,
      "no secret text reached the rendered note view");
  const modalButtons = await until(() => {
    const buttons = qa("#modal-root .modal .actions button");
    return buttons.length ? buttons : null;
  }, "modal buttons", 20);
  if (modalButtons && modalButtons.length) { modalButtons[modalButtons.length - 1].click(); }
  await sleep(400);

  // Opening it again must ask again (the release is a window, not a permission). The hash has
  // to change in between: the SPA treats a deep link to the note it already shows as a no-op.
  location.hash = folderHash;
  await until(() => rowFor("card.md"), "back to the folder", 20);
  row = rowFor("card.md");
  let reopened = false;
  if (row) {
    row.click();
    reopened = !!(await until(() => q("#modal-root .modal pre.plain"), "second ask", 80));
    const again = qa("#modal-root .modal .actions button");
    if (again.length) { again[again.length - 1].click(); }
    await sleep(300);
  }
  log(reopened, "a second click is asked and answered again");

  // ------------------------------------------------------- 2. rename the entry
  row = rowFor("card.md");
  if (row) {
    row.querySelectorAll(".row-action")[0].click();          // ✏️
    const input = await until(() => q("#modal-root input[type=text]"), "the rename dialog", 20);
    log(!!input, "the rename dialog opened");
    if (input) {
      input.value = "card-renamed.md";
      input.dispatchEvent(new Event("input", { bubbles: true }));
      const ok = qa("#modal-root .modal .actions button").filter((b) => b.classList.contains("primary"))[0];
      if (ok) { ok.click(); }
      const renamed = await until(() => rowFor("card-renamed.md"), "the renamed row", 40);
      log(!!renamed, "the rename landed in the listing");
      const badge = renamed ? renamed.querySelector(".badge") : null;
      log(!!badge && badge.textContent.indexOf("🔑") >= 0, "the renamed entry kept its level (🔑)");
    }
  }

  // ------------------------------------------------------- 3. delete the entry
  const target = rowFor("card-renamed.md");
  if (target) {
    target.querySelectorAll(".row-action")[1].click();        // 🗑
    const confirm = await until(() => q("#modal-root .modal .actions button.primary.danger"),
                                "the delete confirmation", 20);
    log(!!confirm, "the delete confirmation opened");
    if (confirm) { confirm.click(); }
    const gone = await until(() => !rowFor("card-renamed.md"), "the row to disappear", 40);
    log(!!gone, "the entry is gone from the listing");
  } else {
    log(false, "the renamed row was not found for deletion");
  }

  return lines;
}
