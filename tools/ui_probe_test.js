async (lines, log, until, sleep) => {
  location.hash = "#/folder/" + encodeURI("الف/ب/ج");
  await until(() => Array.from(document.querySelectorAll("#folder-crumbs button")).length === 4, "crumbs");
  await sleep(600);
  const crumbHTML = document.querySelector("#folder-crumbs").outerHTML.replace(/\s+/g, " ");
  log(true, "crumb markup", crumbHTML.slice(0, 400));
  log(true, "crumb styles", Array.from(document.querySelectorAll("#folder-crumbs .crumb")).map((b) => {
    const s = getComputedStyle(b);
    return b.textContent.trim() + ":" + (b.disabled ? "disabled" : "clickable") + "/" + s.cursor + "/" + s.borderRadius;
  }).join(" | "));
  log(true, "sidebar-actions", Array.from(document.querySelectorAll(".sidebar-actions button"))
    .map((b) => b.textContent.trim()).join(" | "));
  log(true, "tree heading", (document.querySelector(".panel-left .section-title") || {}).textContent);
  return lines;
}
