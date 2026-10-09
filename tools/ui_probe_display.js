/* Display-direction probe (SPEC/10 §B…): every block in the note view follows its own text.
 *
 * Run: ./.venv/bin/python tools/ui_probe.py /tmp/display.png tools/ui_probe_display.js
 *
 * Max's rule: a block with even one Persian/Arabic letter is RTL **and** right-aligned, a block
 * without one is LTR and left-aligned, code is always LTR. This measures the real page (the
 * shipped stylesheet) with computed style *and* geometry: the first line of a block must be flush
 * with the matching edge of its own content box. A control pass re-renders the same blocks with
 * `dir="auto"` (the previous behaviour) and must FAIL — otherwise the check proves nothing.
 */
async (lines, log, until, sleep) => {
  const note = () => document.getElementById("note-body");
  const shown = (id) => {
    const view = document.getElementById(id);
    return !!(view && !view.hidden);
  };
  const dirOf = (el) => (el ? getComputedStyle(el).direction : "(none)");
  const alignOf = (el) => (el ? getComputedStyle(el).textAlign : "(none)");
  const attr = (el) => (el ? el.getAttribute("dir") : null);

  // First line of the element's own text (bidi splits a line into several rects).
  const edges = (el) => {
    const range = document.createRange();
    range.selectNodeContents(el);
    const rects = Array.from(range.getClientRects()).filter((r) => r.width > 0 || r.height > 0);
    if (!rects.length) { return null; }
    const top = Math.min.apply(null, rects.map((r) => r.top));
    const first = rects.filter((r) => Math.abs(r.top - top) < 2);
    return {
      left: Math.min.apply(null, first.map((r) => r.left)),
      right: Math.max.apply(null, first.map((r) => r.right))
    };
  };
  const box = (el) => {
    const rect = el.getBoundingClientRect();
    const style = getComputedStyle(el);
    return {
      left: rect.left + parseFloat(style.paddingLeft || "0"),
      right: rect.right - parseFloat(style.paddingRight || "0")
    };
  };
  const flushRight = (el) => {
    const e = edges(el);
    const b = box(el);
    return !!e && Math.abs(e.right - b.right) <= 8;
  };
  const flushLeft = (el) => {
    const e = edges(el);
    const b = box(el);
    return !!e && Math.abs(e.left - b.left) <= 8;
  };
  const describe = (el) => JSON.stringify((el.textContent || "").trim().slice(0, 22)) + " " +
    attr(el) + "/" + dirOf(el) + "/" + alignOf(el) + "/flush:" +
    (attr(el) === "rtl" ? flushRight(el) : flushLeft(el));

  location.hash = "#/note/" + encodeURI("الف/ب/ج/نمایش.md");
  const loaded = await until(() => shown("view-note") &&
      note().textContent.indexOf("مقایسه نهایی") >= 0, "the fixture note");
  if (!loaded) {
    log(false, "note view", note().textContent.slice(0, 40) || "(empty)");
    return lines;
  }
  await sleep(400);

  const blocks = Array.from(note().querySelectorAll("h1, h2, h3, p, li, td, th, blockquote"));
  const measured = blocks.filter((el) => !el.querySelector("p, li, td, th, table, ul, ol, blockquote"));
  const rtlBad = [];
  const ltrBad = [];
  let rtlCount = 0;
  let ltrCount = 0;
  measured.forEach((el) => {
    if (attr(el) === "rtl") {
      rtlCount += 1;
      if (dirOf(el) !== "rtl" || alignOf(el) !== "right" || !flushRight(el)) { rtlBad.push(describe(el)); }
    } else if (attr(el) === "ltr") {
      ltrCount += 1;
      if (dirOf(el) !== "ltr" || alignOf(el) !== "left" || !flushLeft(el)) { ltrBad.push(describe(el)); }
    } else {
      ltrBad.push("no dir attribute: " + describe(el));
    }
  });
  log(measured.length >= 10, "blocks measured", String(measured.length));
  log(rtlBad.length === 0, "every RTL block is right-aligned and flush right",
      (rtlBad.length ? rtlBad.slice(0, 3).join(" ;; ") : rtlCount + " blocks"));
  log(ltrBad.length === 0, "every LTR block is left-aligned and flush left",
      (ltrBad.length ? ltrBad.slice(0, 3).join(" ;; ") : ltrCount + " blocks"));

  const byText = (needle, tag) => measured.find((el) => el.textContent.indexOf(needle) >= 0 &&
    (!tag || el.tagName === tag));
  const cases = [
    ["a latin-first mixed line is RTL", byText("Quality over quantity"), "rtl"],
    ["a persian paragraph is RTL", byText("متن فارسی با English"), "rtl"],
    ["a persian heading is RTL", byText("مقایسه نهایی"), "rtl"],
    ["a persian quote is RTL", byText("نقل قول فارسی"), "rtl"],
    ["an english-only paragraph stays LTR", byText("plain english line only"), "ltr"],
    ["an english-only list item stays LTR", byText("english bullet only"), "ltr"],
    ["a persian list item is RTL", byText("مورد فارسی"), "rtl"],
    ["a persian numbered item is RTL", byText("با 132%"), "rtl"],
    ["an english numbered item stays LTR", byText("English only numbered item"), "ltr"],
    ["a persian table cell is RTL", byText("گزینه"), "rtl"],
    ["an english table cell stays LTR", byText("RotatE + ComplEx"), "ltr"]
  ];
  cases.forEach((item) => {
    const el = item[1];
    const want = item[2];
    const ok = !!el && attr(el) === want && dirOf(el) === want &&
      alignOf(el) === (want === "rtl" ? "right" : "left") &&
      (want === "rtl" ? flushRight(el) : flushLeft(el));
    log(ok, item[0], el ? describe(el) : "(not found)");
  });

  const table = note().querySelector("table");
  const list = note().querySelector("ol");
  const style = (el) => getComputedStyle(el);
  log(attr(table) === "rtl" && dirOf(table) === "rtl", "the mixed table is RTL", attr(table) || "(none)");
  log(attr(list) === "rtl" && dirOf(list) === "rtl" && parseFloat(style(list).paddingRight) > 0 &&
      parseFloat(style(list).paddingLeft) === 0, "the RTL numbered list keeps its numbers on the right",
      "padding-left:" + style(list).paddingLeft + " padding-right:" + style(list).paddingRight);
  log(dirOf(note().querySelector("pre code")) === "ltr", "code stays LTR");
  log(note().querySelectorAll('[dir="auto"]').length === 0, "no dir=auto is left in the note",
      String(note().querySelectorAll('[dir="auto"]').length));

  // Control: the same markup with dir="auto" (the old behaviour) must not pass the same check.
  const control = document.createElement("div");
  control.setAttribute("data-probe-control", "1");
  control.innerHTML = note().innerHTML.replace(/dir="(?:rtl|ltr)"/g, 'dir="auto"');
  note().appendChild(control);
  await sleep(250);
  const controlMixed = Array.from(control.querySelectorAll("p"))
    .find((el) => el.textContent.indexOf("Quality over quantity") >= 0);
  const controlMixedDir = controlMixed ? dirOf(controlMixed) : "(none)";
  const controlMixedAlign = controlMixed ? alignOf(controlMixed) : "(none)";
  const controlFails = !!controlMixed && !(controlMixedDir === "rtl" && controlMixedAlign === "right" &&
    flushRight(controlMixed));
  log(controlFails, "control with dir=auto fails the same check",
      controlMixed ? controlMixedDir + "/" + controlMixedAlign + "/flush:" + flushRight(controlMixed) : "(none)");
  control.remove();
  return lines;
}
