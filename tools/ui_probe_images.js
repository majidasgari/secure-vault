/* Probe: does opening an image file in the SPA actually show the picture? */
async function (lines, log, until, sleep) {
  const $ = (sel) => document.querySelector(sel);
  const path = "/attachments/dot.png";

  // 1. from the folder view: one click on the row has to open it
  location.hash = "#/folder/" + encodeURIComponent("attachments");
  await until(() => document.querySelectorAll("#notes-list li").length > 0, "attachments list");
  const row = Array.from(document.querySelectorAll("#notes-list li"))
    .find((li) => li.textContent.indexOf("dot.png") >= 0);
  log(!!row, "the picture is listed in its folder");
  if (row) { row.click(); }
  await until(() => !$("#view-note").hidden, "note view after the click");
  log(location.hash.indexOf("#/note/") === 0, "a click on the row navigates to the file", location.hash);

  // 2. the note pane carries a real <img>, and it decodes
  await until(() => !!$("#note-body img"), "image element");
  const img = $("#note-body img");
  log(!!img, "an <img> is rendered in the note pane");
  if (img) {
    await until(() => img.complete, "image load finished");
    log(img.naturalWidth > 0 && img.naturalHeight > 0,
        "the picture decoded", img.naturalWidth + "x" + img.naturalHeight +
        " src=" + String(img.src || "").slice(0, 24));
    const box = img.getBoundingClientRect();
    log(box.width >= 1 && box.height >= 1, "it has a size on screen",
        Math.round(box.width) + "x" + Math.round(box.height));
  }
  log(!$(".broken-image") && !$(".binary-preview"), "no placeholder instead of the picture",
      ($(".broken-image") || $(".binary-preview") || {}).textContent || "");

  // 3. and the deep link works on its own
  location.hash = "#/folder/";
  await until(() => !$("#view-folder").hidden, "back to the folder view");
  location.hash = "#/note/" + encodeURIComponent(path);
  await until(() => !!$("#note-body img"), "image via deep link");
  const deep = $("#note-body img");
  log(!!deep, "a deep link to the picture shows it too");
}
