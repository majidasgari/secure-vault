/* Extra test for tools/ui_probe.py: the visual (Milkdown) editor in the web UI (SPEC/10).
 *
 * Run: ./.venv/bin/python tools/ui_probe.py /tmp/visual.png tools/ui_probe_visual.js
 * It opens the fixture note «ادیتور.md», switches the edit view to the visual editor and measures
 * the real DOM: per-block direction, table/list/task/code rendering, the vault:→blob: image path,
 * typing mirroring into the textarea, the save round trip, teardown on toggle-off, and that nothing
 * cross-origin was requested. (A block comment: the driver prepends `window.__TEST__ = ` inline.)
 */
async (lines, log, until, sleep) => {
  const dir = (el) => (el ? getComputedStyle(el).direction : "(none)");
  const pane = () => document.getElementById("visual-editor");
  const area = () => document.getElementById("editor");
  const shown = (id) => {
    const view = document.getElementById(id);
    return !!(view && !view.hidden);
  };
  const openEditor = async () => {
    const button = document.getElementById("btn-visual");
    if (button.getAttribute("aria-pressed") !== "true") { button.click(); }
    const mounted = await until(() => document.querySelector("#visual-editor .ProseMirror"), "mount", 60);
    await sleep(500);
    return !!mounted;
  };

  location.hash = "#/note/" + encodeURI("الف/ب/ج/ادیتور.md");
  const loaded = await until(() => shown("view-note") &&
      document.getElementById("note-title").textContent.indexOf("ادیتور") >= 0, "the fixture note");
  if (!loaded) {
    log(false, "note view", document.getElementById("note-title").textContent || "(none)");
    return lines;
  }
  document.getElementById("btn-note-edit-top").click();
  log(await until(() => shown("view-edit"), "edit view"), "edit view opened");

  const button = document.getElementById("btn-visual");
  log(!!button && button.textContent.trim() === "ادیتور بصری", "button label is translated",
      button ? JSON.stringify(button.textContent.trim()) : "(none)");

  // The vendored module must be served and must evaluate: a 404 or a broken bundle would otherwise
  // only show up as "the button does nothing".
  window.addEventListener("error", (e) => log(false, "page error", String(e.message)));
  const served = await fetch("/static/vendor/milkdown-editor.js")
    .then((r) => r.status + " " + r.headers.get("content-type")).catch((e) => "ERR " + String(e.message));
  log(served.indexOf("200") === 0, "vendor bundle is served", served);
  const imported = await import("/static/vendor/milkdown-editor.js")
    .then((m) => "exports: " + Object.keys(m).join(",")).catch((e) => "ERR " + String(e.message));
  log(imported.indexOf("exports:") === 0, "vendor bundle evaluates", imported.slice(0, 120));

  log(await openEditor(), "visual editor mounted");
  const pm = document.querySelector("#visual-editor .ProseMirror");
  if (!pm) { return lines; }

  const blocks = Array.from(pm.children);
  const find = (needle) => blocks.find((b) => b.textContent.indexOf(needle) >= 0);
  log(dir(find("متن فارسی")) === "rtl", "persian paragraph is RTL", dir(find("متن فارسی")));
  log(dir(find("An English paragraph")) === "ltr", "english paragraph is LTR",
      dir(find("An English paragraph")));

  const headingDir = (text) => {
    const heading = Array.from(pm.querySelectorAll("h1, h2, h3")).find((h) => h.textContent.indexOf(text) >= 0);
    return heading ? heading.tagName + ":" + dir(heading) : "(missing)";
  };
  const headings = [headingDir("ادیتور بصری"), headingDir("فهرست"), headingDir("english list"), headingDir("کارها")];
  log(headings.join(" ") === "H1:rtl H2:rtl H3:ltr H3:rtl", "headings follow their own text", headings.join(" "));

  const lists = Array.from(pm.querySelectorAll("ul"));
  log(lists.length === 3, "three lists rendered", String(lists.length));
  log(lists.length === 3 && dir(lists[0]) === "rtl" && dir(lists[1]) === "ltr" && dir(lists[2]) === "rtl",
      "list direction follows its items", lists.map((u) => dir(u)).join(","));

  // Crepe draws task items with its own icons instead of a checkbox input.
  const taskList = Array.from(pm.querySelectorAll("ul")).find((u) => u.textContent.indexOf("کار انجام") >= 0);
  log(!!taskList && taskList.querySelectorAll("li.list-item .label.checked").length === 1 &&
      taskList.querySelectorAll("li.list-item .label.unchecked").length === 1,
      "task list rendered", taskList ? Array.from(taskList.querySelectorAll(".label")).map((s) =>
        s.className.replace("milkdown-icon label ", "")).join(",") : "(no task list)");

  log(dir(pm.querySelector("blockquote")) === "rtl", "persian quote is RTL",
      dir(pm.querySelector("blockquote")));

  const tables = Array.from(pm.querySelectorAll(".table-wrapper > table"));
  log(tables.length === 2, "both tables rendered", String(tables.length));
  log(tables.length === 2 && dir(tables[0]) === "rtl" && dir(tables[1]) === "ltr",
      "table direction follows its cells", tables.map((t) => dir(t)).join(","));
  log(dir(pm.querySelector(".table-wrapper > table td, .table-wrapper > table th")) === "rtl",
      "first cell of the persian table is RTL");

  // CodeMirror only initialises once the block is visible, so scroll it into view first.
  const code = pm.querySelector(".milkdown-code-block");
  log(!!code, "code block rendered", code ? code.className : "(none)");
  log(dir(code) === "ltr", "code block is LTR", dir(code));
  log(!!code && !!code.querySelector(".milkdown-code-block-placeholder code"), "code block keeps its text",
      code ? code.textContent.trim().slice(0, 24) : "(none)");
  if (code) {
    code.scrollIntoView({ block: "center" });
    const editor = await until(() => pm.querySelector(".milkdown-code-block .cm-content, " +
        ".milkdown-code-block .codemirror-host"), "the code editor", 25);
    log(!!editor, "code block editor starts when scrolled into view",
        editor ? editor.className.slice(0, 30) : "(placeholder only)");
    log(dir(pm.querySelector(".milkdown-code-block .cm-editor")) === "ltr", "code editor is LTR");
  }

  const images = Array.from(pm.querySelectorAll("img"));
  log(images.length === 1, "the fixture image rendered", String(images.length));
  log(images.length === 1 && String(images[0].src).indexOf("blob:") === 0,
      "vault: image resolved through the vault", images[0] ? String(images[0].src).slice(0, 24) : "(none)");
  log(images.length === 1 && images[0].naturalWidth > 0, "image bytes decoded",
      images[0] ? images[0].naturalWidth + "x" + images[0].naturalHeight : "0");

  log(area().hidden === true, "textarea is hidden while the visual editor is up");
  const toolbar = document.querySelector(".format-toolbar");
  log(!!toolbar && toolbar.hidden === true, "markdown toolbar gives way to crepe's own");
  const crossOrigin = performance.getEntriesByType("resource")
    .map((e) => e.name)
    .filter((n) => n.indexOf("blob:") !== 0 && n.indexOf("data:") !== 0 &&
                   new URL(n, location.href).origin !== location.origin);
  log(crossOrigin.length === 0, "no cross-origin request", crossOrigin.slice(0, 3).join(" "));
  log(performance.getEntriesByType("resource")
      .filter((e) => e.name.indexOf("/static/vendor/milkdown-editor.js") >= 0).length === 1,
      "vendor bundle fetched exactly once");

  // Toggle off: the pane is torn down and the plain textarea returns with the same text.
  button.click();
  const closed = await until(() => pane().hidden && pane().childNodes.length === 0, "teardown", 30);
  log(!!closed, "toggling off unmounts the editor");
  log(area().hidden === false, "textarea is back");
  log(button.getAttribute("aria-pressed") === "false", "button leaves the pressed state");
  const before = area().value;

  // Back on: the mode is remembered for this tab, so re-entering the view mounts it again.
  log(await openEditor(), "visual editor remounts");
  log(area().value === before, "remount keeps the same markdown",
      JSON.stringify(area().value.slice(0, 20)));

  // Typing in the visual editor must reach the textarea: the dirty guard and Save read *it*.
  const paragraph = Array.from(document.querySelector("#visual-editor .ProseMirror").children)
    .find((b) => b.textContent.indexOf("متن فارسی") >= 0);
  const range = document.createRange();
  range.selectNodeContents(paragraph);
  range.collapse(false);
  const selection = window.getSelection();
  selection.removeAllRanges();
  selection.addRange(range);
  document.querySelector("#visual-editor .ProseMirror").focus();
  const inserted = document.execCommand("insertText", false, " [تایپ‌شده]");
  const mirrored = await until(() => area().value.indexOf("[تایپ‌شده]") >= 0, "the mirror", 20);
  log(inserted, "insertText was accepted", String(inserted));
  log(!!mirrored, "typing mirrors into the textarea",
      JSON.stringify((area().value.split("\n")[2] || "")).slice(0, 80));
  log(document.getElementById("dirty-indicator").hidden === false, "the note is marked dirty");

  // Save → the note view, with the editor gone and the new text in the article.
  document.getElementById("btn-save").click();
  const saved = await until(() => shown("view-note"), "the note view after save", 40);
  log(!!saved, "save returns to the note view");
  const inBody = await until(() => document.getElementById("note-body").textContent.indexOf("تایپ‌شده") >= 0,
      "the saved text in the article", 30);
  log(!!inBody, "the typed text is in the saved note",
      JSON.stringify(document.getElementById("note-body").textContent.slice(0, 50)));
  log(pane().hidden === true && pane().childNodes.length === 0, "saving tears the editor down");

  // And it survives a reload of the note from the vault.
  location.hash = "#/folder/" + encodeURI("الف/ب/ج");
  await until(() => shown("view-folder"), "the folder view");
  location.hash = "#/note/" + encodeURI("الف/ب/ج/ادیتور.md");
  const reread = await until(() => shown("view-note") &&
      document.getElementById("note-body").textContent.indexOf("تایپ‌شده") >= 0, "the note from disk", 40);
  log(!!reread, "the edit came back from the vault");
  return lines;
}
