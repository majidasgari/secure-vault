/* Probe: the learning cycle in the SPA — badge, due/upcoming split, the card, seen/reset/stop and
 * the note's own entry. Run:
 *   ./.venv/bin/python tools/ui_probe.py /tmp/learn.png tools/ui_probe_learning.js
 * The fixture (tools/ui_probe.py build_vault) seeds one card three days late and one due tomorrow.
 */
async function (lines, log, until, sleep) {
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));
  const text = (el) => (el ? el.textContent.trim() : "");
  const rowTexts = (sel) => $$(sel).map((li) => li.textContent.trim());

  // 1. the entry lives in the sidebar and counts today's queue
  log(!!$("#btn-learn"), "learning entry in the sidebar");
  const badge = $("#learn-count");
  log(!!badge && !badge.hidden && text(badge) === "1", "the badge counts today's card", text(badge));

  // 2. the view splits the late card from the next one
  location.hash = "#/learn";
  await until(() => !$("#view-learn").hidden && $$("#learn-due li").length > 0, "learning view");
  log(!$("#view-learn").hidden, "learning view visible");
  const due = rowTexts("#learn-due li");
  log(due.length === 1 && due[0].indexOf("یادداشت.md") >= 0, "the late card is in today's list", due.join(" / "));
  log(/3 روز عقب/.test(due.join(" ")), "the row says how late it is", due.join(" "));
  const ahead = rowTexts("#learn-upcoming li");
  log(ahead.length === 1 && ahead[0].indexOf("عمیق.md") >= 0, "tomorrow's card is in the upcoming list", ahead.join(" / "));
  log($("#learn-due-empty").hidden, "no empty line while a card waits");

  // 3. the flashcard: text hidden until asked for, then the note's own rendering
  $("#learn-due li").click();
  await until(() => !$("#learn-card").hidden, "card open");
  log(!$("#learn-card").hidden, "the card opened");
  log($("#learn-card-body").hidden, "the text starts hidden");
  const meta = text($("#learn-card-meta"));
  log(/مرحلهٔ 2 از 6/.test(meta), "the card names the stage", meta);
  $("#btn-learn-reveal").click();
  await until(() => !$("#learn-card-body").hidden && $("#learn-card-body").innerHTML.length > 0, "revealed");
  log(!$("#learn-card-body").hidden, "reveal shows the text");
  log($("#learn-card-body").textContent.indexOf("یادداشت") >= 0, "the body is the note itself", text($("#learn-card-body")).slice(0, 40));
  $("#btn-learn-reveal").click();
  log($("#learn-card-body").hidden, "reveal toggles back");

  // 4. «خوندم» moves the card to its next interval and out of today's queue
  $("#btn-learn-seen").click();
  await until(() => $$("#learn-due li").length === 0, "due list empties");
  log($$("#learn-due li").length === 0, "the reviewed card left today's queue");
  const moved = rowTexts("#learn-upcoming li").join(" / ");
  log(moved.indexOf("یادداشت.md") >= 0, "it moved to the upcoming list", moved);
  log($("#learn-count").hidden, "the badge cleared");
  log(!$("#learn-due-empty").hidden, "the empty line appears");
  log($("#learn-card").hidden, "no card stays open on an empty queue");

  // 5. «از اول» restarts the cycle — after asking
  const restart = $$("#learn-upcoming li").find((li) => li.textContent.indexOf("یادداشت.md") >= 0);
  restart.click();
  await until(() => !$("#learn-card").hidden, "card reopens");
  $("#btn-learn-reset").click();
  await until(() => !!document.querySelector(".modal-backdrop"), "reset question");
  log(!!document.querySelector(".modal-backdrop"), "reset asks before it acts");
  const confirmReset = $$(".modal-backdrop button").find((b) => b.textContent.trim() === "از اول");
  log(!!confirmReset, "the question carries the reset label");
  if (confirmReset) { confirmReset.click(); }
  await until(() => /مرحلهٔ 1 از 6/.test(text($("#learn-card-meta"))), "stage back to one");
  log(/مرحلهٔ 1 از 6/.test(text($("#learn-card-meta"))), "the card is back at stage 1", text($("#learn-card-meta")));
  log(text($("#learn-upcoming li")).length > 0, "a restarted card is due tomorrow, so it stays ahead");

  // 6. «خروج از یادگیری» takes it out of the cycle
  $("#btn-learn-stop").click();
  await until(() => !!document.querySelector(".modal-backdrop"), "stop question");
  const confirmStop = $$(".modal-backdrop button").find((b) => b.textContent.trim() === "خروج از یادگیری");
  if (confirmStop) { confirmStop.click(); }
  await until(() => $("#learn-card").hidden, "card removed");
  log($("#learn-card").hidden, "the card closed");
  const left = rowTexts("#learn-upcoming li").join(" / ");
  log(left.indexOf("یادداشت.md") < 0, "the stopped card left the cycle", left);
  log(left.indexOf("عمیق.md") >= 0, "the other card stays in its own cycle", left);

  // 7. the note's own button: add, then it names the new state and the badge returns
  location.hash = "#/folder/" + encodeURIComponent("الف/ب/ج");
  await until(() => $$("#notes-list li").length > 0, "folder list");
  const row = $$("#notes-list li").find((li) => li.textContent.indexOf("یادداشت.md") >= 0);
  log(!!row, "the note is listed in its folder");
  if (row) { row.click(); }
  await until(() => !$("#view-note").hidden && !!$("#btn-note-learn-top"), "note view");
  log(text($("#btn-note-learn-top")) === "افزودن به یادگیری", "a plain note offers to join the cycle", text($("#btn-note-learn-top")));
  $("#btn-note-learn-top").click();
  await until(() => text($("#btn-note-learn-top")) === "در یادگیری", "note joined");
  log(text($("#btn-note-learn-top")) === "در یادگیری", "the button now names the state", text($("#btn-note-learn-top")));
  location.hash = "#/learn";
  await until(() => !$("#view-learn").hidden && rowTexts("#learn-upcoming li").join(" ").indexOf("یادداشت.md") >= 0, "note in the ahead list");
  log(rowTexts("#learn-upcoming li").join(" / ").indexOf("یادداشت.md") >= 0, "the view follows the note's own button", rowTexts("#learn-upcoming li").join(" / "));

  // 8. on a phone the entry has to be inside the drawer, and the drawer has to be reachable
  if (window.innerWidth <= 860) {
    $("#btn-menu").click();
    await sleep(450);
    const box = $("#btn-learn").getBoundingClientRect();
    const hit = document.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2);
    log(!!hit && $("#panel-left").contains(hit), "the learning entry is reachable in the phone drawer", Math.round(box.left) + "x" + Math.round(box.width));
    location.hash = "#/learn";
    await until(() => !$("#view-learn").hidden, "learning view on phone");
    await sleep(300);
    // A card open is the tightest the layout gets: five actions in one row.
    const firstRow = $$("#learn-due li")[0] || $$("#learn-upcoming li")[0];
    if (firstRow) { firstRow.click(); }
    await until(() => !$("#learn-card").hidden, "card on phone");
    await sleep(300);
    const wide = $("#view-learn").getBoundingClientRect().width;
    log(document.documentElement.scrollWidth <= window.innerWidth + 1, "the learning view (with a card) fits the phone width", Math.round(wide) + "/" + window.innerWidth + " scroll=" + document.documentElement.scrollWidth);
    const actions = $("#learn-card .note-actions").getBoundingClientRect();
    log(actions.right <= window.innerWidth + 1 && actions.left >= -1, "the card's actions stay on the screen", Math.round(actions.left) + ".." + Math.round(actions.right));
  }
}
