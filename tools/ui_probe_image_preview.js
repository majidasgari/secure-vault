/* Probe: pointing at an image row shows the picture (attachments are hash-named). */
async function (lines, log, until, sleep) {
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  location.hash = "#/folder/" + encodeURIComponent("attachments");
  await until(() => $$("#notes-list li").length > 0, "attachments list");
  const row = $$("#notes-list li").find((li) => li.textContent.indexOf("sample.png") >= 0);
  log(!!row, "the picture row is listed");
  if (!row) { return; }

  row.dispatchEvent(new MouseEvent("mouseenter"));
  await until(() => {
    const node = document.getElementById("image-preview");
    return !!node && !node.hidden;
  }, "preview shown");
  const img = document.getElementById("image-preview");
  log(!!img && !img.hidden, "hovering the row shows a preview");
  await until(() => img.complete && img.naturalWidth > 0, "thumbnail decoded");
  log(img.naturalWidth === 320 && img.naturalHeight === 200, "the preview is the picture itself",
      img.naturalWidth + "x" + img.naturalHeight + " src=" + String(img.src || "").slice(0, 12));
  const box = img.getBoundingClientRect();
  log(box.width <= 241 && box.height <= 241 && box.width > 100,
      "a big picture is scaled down to a thumbnail",
      Math.round(box.width) + "x" + Math.round(box.height));
  log(box.left >= 0 && box.top >= 0 && box.right <= window.innerWidth + 1,
      "it stays on screen",
      Math.round(box.left) + "," + Math.round(box.top));

  row.dispatchEvent(new MouseEvent("mouseleave"));
  await sleep(150);
  log(document.getElementById("image-preview").hidden, "leaving the row hides it again");

  location.hash = "#/folder/" + encodeURIComponent("الف/ب/ج");
  await until(() => $$("#notes-list li").length > 0, "note list");
  const note = $$("#notes-list li").find((li) => li.textContent.indexOf("یادداشت.md") >= 0);
  if (note) { note.dispatchEvent(new MouseEvent("mouseenter")); }
  await sleep(500);
  log(document.getElementById("image-preview").hidden, "a note row previews nothing");

  // The picture still opens in the note pane on a click (the preview is an extra, not a swap).
  if (row) {
    location.hash = "#/folder/" + encodeURIComponent("attachments");
    const again = await until(
      () => $$("#notes-list li").find((li) => li.textContent.indexOf("sample.png") >= 0),
      "the picture row again"
    );
    if (!again) { return; }
    again.click();
    await until(() => !!$("#note-body img"), "picture opened");
    log(!!$("#note-body img"), "a click still opens the picture in the pane");
  }
}
