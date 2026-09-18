/* Secure Vault web UI (SPEC/07 §4 + SPEC/07b parity).
 * Plain ES2020, no imports, no build step, no network dependencies.
 * Every user-visible string comes from /api/i18n; nothing vault-related is written to
 * session storage or the URL, and no secret/secretfile content ever reaches an HTML path.
 */
(function () {
  "use strict";

  var TOKEN_KEY = "vault_token";
  var LANG_KEY = "vault_lang";
  var THEME_KEY = "vault_theme";

  var TOOLBAR_ACTIONS = [
    ["bold", "B"],
    ["italic", "I"],
    ["strike", "S"],
    ["code", "</>"],
    ["heading", "H"],
    ["quote", "❝"],
    ["ul", "•"],
    ["ol", "1."],
    ["link", "🔗"],
    ["image", "🖼"],
    ["hr", "―"]
  ];

  var state = {
    token: "",
    lang: "fa",
    theme: "dark",
    catalogue: {},
    session: null,
    index: { tree: [], tags: [], counts: {} },
    cwd: "/",
    languages: ["fa", "en"],
    file: null,
    dirty: false,
    preview: false,
    searchKind: "filenames",
    logOffset: 0,
    logEntries: [],
    activity: [],
    eventAbort: null,
    busy: 0,
    lastActivity: Date.now(),
    selectedIndex: -1,
    editing: false
  };

  var statusBase = "";

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  /* ----------------------------------------------------------------- i18n */
  function t(key, params) {
    var template = state.catalogue[key];
    if (template === undefined) { return "\u27e6" + key + "\u27e7"; }
    if (params) {
      template = template.replace(/\{(\w+)\}/g, function (match, name) {
        return Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : match;
      });
    }
    return template;
  }

  function applyI18n(root) {
    $$("[data-i18n]", root || document).forEach(function (el) {
      el.textContent = t(el.getAttribute("data-i18n"));
    });
    $$("[data-i18n-placeholder]", root || document).forEach(function (el) {
      el.setAttribute("placeholder", t(el.getAttribute("data-i18n-placeholder")));
    });
    $$("[data-i18n-title]", root || document).forEach(function (el) {
      el.setAttribute("title", t(el.getAttribute("data-i18n-title")));
    });
    document.title = t("web.title");
  }

  function applyDirection() {
    var rtl = state.lang === "fa";
    document.documentElement.lang = state.lang;
    document.documentElement.dir = rtl ? "rtl" : "ltr";
  }

  function applyTheme() {
    document.documentElement.setAttribute("data-theme", state.theme);
  }

  function setLanguage(lang) {
    state.lang = lang;
    renderLanguageSelects();
    try { sessionStorage.setItem(LANG_KEY, lang); } catch (e) { /* private mode */ }
    applyDirection();
    loadCatalogue().then(function () {
      applyI18n();
      renderTree();
      renderTagChips();
      refreshStatusBar();
      if (state.file) { renderNoteView(); }
    });
  }

  function toggleTheme() {
    state.theme = state.theme === "dark" ? "light" : "dark";
    try { sessionStorage.setItem(THEME_KEY, state.theme); } catch (e) { /* ignore */ }
    applyTheme();
  }

  function loadCatalogue() {
    return request("GET", "/api/i18n?lang=" + encodeURIComponent(state.lang)).then(function (r) {
      if (r.ok && r.data) {
        state.catalogue = r.data;
        if (Array.isArray(r.data._languages) && r.data._languages.length) {
          state.languages = r.data._languages;
        }
      }
      renderLanguageSelects();
    }).catch(function () { /* keep whatever we have */ });
  }

  function renderLanguageSelects() {
    // One <select> instead of a button per language: a new i18n/*.json then shows up here
    // without touching the SPA.
    var langs = (state.languages && state.languages.length) ? state.languages : [state.lang || "fa"];
    ["#lang-select", "#lang-select-login"].forEach(function (selector) {
      var select = $(selector);
      if (!select) { return; }
      select.textContent = "";
      langs.forEach(function (code) {
        var option = document.createElement("option");
        option.value = code;
        option.textContent = t("language." + code) === "language." + code ? code : t("language." + code);
        select.appendChild(option);
      });
      select.value = state.lang;
      select.hidden = langs.length < 2;
    });
  }

  /* ------------------------------------------------------------- transport */
  function ApiError(code, status, details) {
    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.details = details || {};
    this.message = code;
  }
  ApiError.prototype = Object.create(Error.prototype);

  function request(method, path, options) {
    options = options || {};
    var headers = {};
    if (state.token) { headers["X-Vault-Token"] = state.token; }
    if (options.headers) {
      Object.keys(options.headers).forEach(function (k) { headers[k] = options.headers[k]; });
    }
    var body;
    if (options.body !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(options.body);
    }
    return fetch(path, { method: method, headers: headers, body: body }).catch(function (err) {
      // A dead server means this tab belongs to an earlier run of the app: say so instead of
      // showing a wall of broken images.
      showStaleBanner();
      throw err;
    }).then(function (res) {
      if (options.raw) { return { status: res.status, ok: res.ok, response: res }; }
      return res.json().catch(function () { return null; }).then(function (data) {
        return { status: res.status, ok: res.ok, data: data };
      });
    });
  }

  function call(method, params) {
    return request("POST", "/api/call", { body: { method: method, params: params || {} } }).then(function (r) {
      if (r.status === 401) { onUnauthorized(); throw new ApiError("UNAUTHORIZED", 401); }
      if (!r.ok || !r.data || r.data.ok === false) {
        var err = (r.data && r.data.error) || { code: "ERROR", message: "", details: {} };
        throw new ApiError(err.code, r.status, err);
      }
      return r.data.result;
    });
  }

  function errorText(err) {
    if (err && err.code && state.catalogue["error." + err.code] !== undefined) {
      return t("error." + err.code);
    }
    return t("error.ERROR");
  }

  /* ------------------------------------------------------------------ auth */
  function onUnauthorized() {
    state.token = "";
    try { sessionStorage.removeItem(TOKEN_KEY); } catch (e) { /* ignore */ }
    showLogin(t("web.bad_token"));
  }

  function showLogin(message) {
    $("#app-view").hidden = true;
    $("#login-view").hidden = false;
    $("#login-error").hidden = !message;
    $("#login-error").textContent = message || "";
    $("#password-input").value = "";
    $("#token-input").value = state.token || "";
  }

  function setTokenVisibility(hasToken) {
    // With a token (claimed from the desktop app, given in the URL or stored earlier) the manual
    // token block stays out of the way; the link lets the user paste a different one.
    var block = $("#token-block");
    var toggle = $("#token-toggle");
    var hint = $("#claim-hint");
    if (block) { block.hidden = !!hasToken; }
    if (toggle) { toggle.hidden = !hasToken; }
    if (hint) { hint.hidden = !!hasToken; }
  }

  function claimToken() {
    // Ask the desktop app on this machine for the access token (loopback only, and the custom
    // header makes the reply unreadable for a random web page).
    return request("POST", "/api/session/claim", { headers: { "X-Vault-Claim": "1" } })
      .then(function (r) {
        if (!r.ok || !r.data || r.data.ok !== true || !r.data.token) { return false; }
        state.token = r.data.token;
        try { sessionStorage.setItem(TOKEN_KEY, state.token); } catch (e) { /* ignore */ }
        return true;
      })
      .catch(function () { return false; });
  }

  function showApp() {
    $("#login-view").hidden = true;
    $("#app-view").hidden = false;
  }

  function handleLogin(event) {
    event.preventDefault();
    var token = $("#token-input").value.trim();
    var password = $("#password-input").value;
    $("#login-error").hidden = true;
    $("#login-lockout").hidden = true;
    if (!token) { setLoginError(t("web.token")); return; }
    request("POST", "/api/session/login", { body: { token: token } }).then(function (r) {
      if (!r.ok || !r.data || r.data.ok !== true) {
        setLoginError(t("error.UNAUTHORIZED"));
        return null;
      }
      state.token = token;
      try { sessionStorage.setItem(TOKEN_KEY, token); } catch (e) { /* ignore */ }
      return loadCatalogue().then(function () {
        applyI18n();
        return doUnlock(password);
      });
    }).catch(function () { setLoginError(t("error.ERROR")); });
  }

  function setLoginError(message) {
    $("#login-error").hidden = false;
    $("#login-error").textContent = message;
  }

  function doUnlock(password) {
    return request("POST", "/api/session/unlock", { body: { password: password } }).then(function (r) {
      if (r.ok && r.data && r.data.ok === true) { return enterApp(); }
      var err = (r.data && r.data.error) || {};
      if (err.code === "UNAUTHORIZED") {
        var reason = err.details && err.details.reason;
        setLoginError(reason === "bad_password" ? t("unlock.wrong_password") : t("error.UNAUTHORIZED"));
        var wait = err.details && err.details.retry_after;
        if (wait) { showLockout(wait); }
      } else {
        setLoginError(errorText(err));
      }
    });
  }

  function showLockout(seconds) {
    var el = $("#login-lockout");
    el.hidden = false;
    var remaining = Number(seconds) || 0;
    function tick() {
      if (remaining <= 0) { el.hidden = true; return; }
      el.textContent = t("unlock.locked_out", { seconds: remaining });
      remaining -= 1;
      window.setTimeout(tick, 1000);
    }
    tick();
  }

  function enterApp() {
    return loadSession().then(function () {
      showApp();
      applyI18n();
      refreshStatusBar();
      loadFont();
      return loadIndex();
    }).then(function () {
      connectEvents();
      startAutoLock();
      applyRoute();
    });
  }

  function loadSession() {
    return request("GET", "/api/session").then(function (r) {
      if (r.status === 401) { onUnauthorized(); throw new ApiError("UNAUTHORIZED", 401); }
      state.session = r.data || {};
      if (state.session && state.session.language && !sessionStorage.getItem(LANG_KEY)) {
        state.lang = state.session.language;
        applyDirection();
      }
      return state.session;
    });
  }

  /* ---------------------------------------------------------------- index */
  function loadIndex() {
    return request("GET", "/api/index").then(function (r) {
      if (r.status === 401) { onUnauthorized(); throw new ApiError("UNAUTHORIZED", 401); }
      if (r.ok && r.data) {
        state.index = {
          tree: r.data.tree || [],
          tags: r.data.tags || [],
          counts: r.data.counts || {}
        };
      }
      renderTree();
      renderTagChips();
      refreshStatusBar();
    }).catch(function () { /* metadata may be unavailable mid-lock */ });
  }

  function renderTree() {
    var tree = $("#folder-tree");
    tree.textContent = "";
    var filter = $("#filter-input").value.trim().toLowerCase();
    state.index.tree.forEach(function (node) {
      if (node.is_dir) { tree.appendChild(buildTreeRow(node, filter)); }
    });
  }

  function buildTreeRow(node, filter) {
    var li = document.createElement("li");
    li.className = "tree-row" + (node.path === state.cwd ? " selected" : "");
    var caret = document.createElement("span");
    caret.className = "caret";
    caret.textContent = "▸";
    var label = document.createElement("span");
    label.className = "tree-name";
    label.dir = "auto";
    label.textContent = node.name;
    var count = document.createElement("span");
    count.className = "tree-count";
    count.textContent = String(node.note_count || 0);
    li.appendChild(caret);
    li.appendChild(label);
    li.appendChild(count);
    li.addEventListener("click", function (ev) {
      if (ev.target === caret) {
        caret.textContent = caret.textContent === "▸" ? "▾" : "▸";
        if (childList) { childList.hidden = !childList.hidden; }
        return;
      }
      navigateFolder(node.path);
    });
    var childList = null;
    var dirs = (node.children || []).filter(function (child) { return child.is_dir; });
    if (dirs.length) {
      childList = document.createElement("ul");
      childList.className = "tree-children";
      childList.hidden = true;
      dirs.forEach(function (child) { childList.appendChild(buildTreeRow(child, filter)); });
    }
    var wrapper = document.createElement("div");
    wrapper.appendChild(li);
    if (childList) { wrapper.appendChild(childList); }
    var box = document.createElement("li");
    box.className = "tree-node";
    box.appendChild(wrapper);
    return box;
  }

  //: How many tags the sidebar shows before deferring to the tag browser.
  var TAG_PREVIEW = 8;

  function sortedTags() {
    return (state.index.tags || []).slice().sort(function (a, b) {
      return (b.count || 0) - (a.count || 0) || String(a.name).localeCompare(String(b.name));
    });
  }

  function tagChip(tag, withCount) {
    var chip = document.createElement("button");
    chip.type = "button";
    chip.className = "chip";
    chip.dir = "auto";
    chip.textContent = withCount ? (tag.name + " " + tag.count) : tag.name;
    chip.title = t("web.tag_heading", { tag: tag.name });
    chip.addEventListener("click", function () { openTag(tag.name); });
    return chip;
  }

  function renderTagChips() {
    var box = $("#tag-chips");
    if (!box) { return; }
    box.textContent = "";
    var tags = sortedTags();
    if (!tags.length) {
      var empty = document.createElement("p");
      empty.className = "muted small";
      empty.textContent = t("web.tags_empty");
      box.appendChild(empty);
      return;
    }
    // Dumping every tag into the sidebar stops working past a few dozen, so only the most used
    // ones stay visible and the rest open in a searchable browser.
    tags.slice(0, TAG_PREVIEW).forEach(function (tag) { box.appendChild(tagChip(tag, true)); });
    if (tags.length > TAG_PREVIEW) {
      var more = document.createElement("button");
      more.type = "button";
      more.className = "chip more";
      more.id = "btn-all-tags";
      more.textContent = t("web.all_tags", { count: tags.length });
      more.addEventListener("click", showTagBrowser);
      box.appendChild(more);
    }
  }

  function showTagBrowser() {
    var modal = buildModal(t("web.tags_heading"));
    openModal(modal.root);
    var filter = document.createElement("input");
    filter.type = "search";
    filter.dir = "auto";
    filter.placeholder = t("web.tag_filter");
    modal.body.appendChild(filter);
    var list = document.createElement("ul");
    list.className = "tag-list";
    modal.body.appendChild(list);
    var close = document.createElement("button");
    close.type = "button";
    close.textContent = t("web.close");
    modal.actions.appendChild(close);
    close.addEventListener("click", function () { modal.root.remove(); });
    var tags = sortedTags();
    function draw(needle) {
      list.textContent = "";
      var shown = 0;
      tags.forEach(function (tag) {
        if (needle && tag.name.toLowerCase().indexOf(needle) < 0) { return; }
        shown += 1;
        var li = document.createElement("li");
        var name = document.createElement("span");
        name.dir = "auto";
        name.textContent = tag.name;
        var count = document.createElement("span");
        count.className = "tree-count";
        count.textContent = String(tag.count || 0);
        li.appendChild(name);
        li.appendChild(count);
        li.addEventListener("click", function () { modal.root.remove(); openTag(tag.name); });
        list.appendChild(li);
      });
      if (!shown) {
        var none = document.createElement("li");
        none.className = "muted";
        none.textContent = t("web.tags_empty");
        list.appendChild(none);
      }
    }
    filter.addEventListener("input", function () { draw(filter.value.trim().toLowerCase()); });
    draw("");
    window.setTimeout(function () { filter.focus(); }, 0);
  }

  function openTag(tag) {
    window.location.hash = "#/tag/" + encodeURIComponent(tag);
  }

  function loadTag(tag) {
    pushBusy();
    call("vault.files_by_tag", { tag: tag }).then(function (result) {
      renderTagCrumbs(tag);
      $("#tag-heading").textContent = t("web.tag_heading", { tag: tag }) +
        " · " + t("web.results_count", { count: result.count || 0 });
      var list = $("#tag-results");
      list.textContent = "";
      (result.results || []).forEach(function (entry) {
        var li = document.createElement("li");
        // notes-list rows reuse .note-row, which is what carries cursor: pointer + hover.
        li.className = "note-row";
        var name = document.createElement("span");
        name.dir = "auto";
        name.textContent = entry.name || String(entry.logical_path).split("/").pop();
        li.appendChild(name);
        var path = document.createElement("span");
        path.className = "meta";
        path.dir = "auto";
        path.textContent = entry.logical_path || entry.path || "";
        li.appendChild(path);
        li.appendChild(rowDeleteButton(entry));
        li.title = t("menu.open");
        li.addEventListener("click", function () { navigateNote(entry.logical_path || entry.path); });
        list.appendChild(li);
      });
      showView("tag");
    }).catch(function (err) { showToast(errorText(err), "error"); }).then(popBusy);
  }

  function renderTagCrumbs(tag) {
    var nav = $("#tag-crumbs");
    if (!nav) { return; }
    nav.textContent = "";
    var all = document.createElement("button");
    all.type = "button";
    all.className = "crumb";
    all.textContent = t("web.tags_heading");
    all.title = t("web.all_tags_title");
    all.addEventListener("click", showTagBrowser);
    nav.appendChild(all);
    var sep = document.createElement("span");
    sep.className = "crumb-sep";
    sep.textContent = "›";
    nav.appendChild(sep);
    var current = document.createElement("button");
    current.type = "button";
    current.className = "crumb current";
    current.dir = "auto";
    current.textContent = tag;
    current.setAttribute("aria-current", "page");
    current.disabled = true;
    nav.appendChild(current);
  }

  /* -------------------------------------------------------------- routing */
  function navigateFolder(path) {
    closeMobilePanels();
    window.location.hash = "#/folder" + (path === "/" ? "/" : path);
  }

  function navigateNote(path) {
    window.location.hash = "#/note" + path;
  }

  function applyRoute() {
    var hash = window.location.hash || "#/folder/";
    if (hash.indexOf("#/note/") === 0) {
      var path = decodeURIComponent(hash.slice("#/note".length)).replace(/^\/+/, "/");
      openFile({ path: path, name: path.split("/").pop() });
      return;
    }
    if (hash.indexOf("#/tag/") === 0) {
      // A tag listing is a real location, so Back (and a reload) returns to it.
      var tag = decodeURIComponent(hash.slice("#/tag".length)).replace(/^\/+/, "");
      if (tag) { loadTag(tag); }
      return;
    }
    if (hash.indexOf("#/folder/") === 0) {
      var folder = (decodeURIComponent(hash.slice("#/folder".length)) || "/").replace(/^\/+/, "/");
      loadFolder(folder);
      return;
    }
    loadFolder("/");
  }

  /* ------------------------------------------------------------- browsing */
  function loadFolder(path) {
    state.cwd = path || "/";
    state.editing = false;
    return call("vault.list_folder", { path: state.cwd }).then(function (result) {
      renderBreadcrumbs($("#folder-crumbs"), state.cwd, navigateFolder);
      renderTree();
      renderFileList(result.entries);
      renderFolderView(result.entries);
      if (result.note !== undefined && result.note !== null) {
        $("#folder-note-input") && ($("#folder-note-input").value = result.note);
      }
      showView("folder");
      refreshStatusBar();
    }).catch(function (err) {
      showToast(errorText(err), "error");
    });
  }

  function renderBreadcrumbs(nav, path, handler, options) {
    // Every crumb carries its own target. The naive version reused the loop variable (`var
    // prefix`), so all chips ended up pointing at the *last* folder and clicking them looked
    // dead: the hash never changed. Copy the value per item.
    if (!nav) { return; }
    var opts = options || {};
    var parts = String(path || "/").split("/").filter(function (part) { return part; });
    var items = [{ label: t("web.breadcrumb_root"), path: "/" }];
    var prefix = "";
    parts.forEach(function (part) {
      prefix = prefix + "/" + part;
      items.push({ label: part, path: prefix.slice() });
    });
    nav.textContent = "";
    items.forEach(function (item, index) {
      if (index) {
        var sep = document.createElement("span");
        sep.className = "crumb-sep";
        sep.textContent = "›";
        nav.appendChild(sep);
      }
      var current = index === items.length - 1;
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "crumb" + (current ? " current" : "");
      btn.dir = "auto";
      btn.textContent = item.label;
      if (current) {
        // Already here — and in a note's breadcrumb the last item is the file, not a folder.
        btn.setAttribute("aria-current", "page");
        btn.title = opts.file ? item.path : t("web.breadcrumb_current");
        btn.disabled = true;
      } else {
        btn.title = item.path;
        btn.addEventListener("click", function () { handler(item.path); });
      }
      nav.appendChild(btn);
    });
  }

  function renderFileList(entries) {
    // The sidebar no longer repeats the folder's files: the centre view is the single list, with
    // dates and full names. Only the filtered model is kept so arrow keys have something to walk.
    var filter = $("#filter-input").value.trim().toLowerCase();
    state.files = entries.filter(function (e) {
      return !e.is_dir && (!filter || e.name.toLowerCase().indexOf(filter) >= 0);
    });
    state.selectedIndex = -1;
  }

  function subtreeNoteCounts() {
    var map = {};
    function walk(nodes) {
      (nodes || []).forEach(function (node) {
        if (node.is_dir) {
          map[node.path] = Number(node.note_count) || 0;
          walk(node.children);
        }
      });
    }
    walk(state.index.tree);
    return map;
  }

  function rowDeleteButton(entry) {
    var button = document.createElement("button");
    button.type = "button";
    button.className = "row-action";
    button.textContent = "🗑";
    button.title = t("menu.delete");
    button.setAttribute("aria-label", t("menu.delete") + ": " + (entry.name || entry.path));
    button.addEventListener("click", function (ev) {
      ev.stopPropagation();
      ev.preventDefault();
      deleteEntry(entry);
    });
    return button;
  }

  function renderFolderView(entries) {
    var dirs = entries.filter(function (e) { return e.is_dir; });
    var files = entries.filter(function (e) { return !e.is_dir; });
    var counts = subtreeNoteCounts();
    var notebooks = $("#notebook-list");
    notebooks.textContent = "";
    dirs.forEach(function (entry) {
      var li = document.createElement("li");
      li.className = "notebook";
      var icon = document.createElement("span");
      icon.textContent = "📁";
      var name = document.createElement("span");
      name.dir = "auto";
      name.textContent = entry.name;
      var count = document.createElement("span");
      count.className = "tree-count";
      count.textContent = String(counts[entry.path] || 0);
      li.appendChild(icon);
      li.appendChild(name);
      li.appendChild(count);
      li.appendChild(rowDeleteButton(entry));
      li.addEventListener("click", function () { navigateFolder(entry.path); });
      notebooks.appendChild(li);
    });
    $("#notes-heading").textContent = t("web.notes") + " (" + files.length + ")";
    var notes = $("#notes-list");
    notes.textContent = "";
    files.forEach(function (entry) {
      var li = document.createElement("li");
      li.className = "note-row";
      var badge = document.createElement("span");
      badge.className = "badge";
      badge.textContent = levelIcon(entry.sensitivity);
      var name = document.createElement("span");
      name.dir = "auto";
      name.textContent = entry.name;
      var date = document.createElement("span");
      date.className = "meta";
      date.textContent = formatDate(entry.mtime);
      li.appendChild(badge);
      li.appendChild(name);
      li.appendChild(date);
      if (entry.note) {
        var noteSpan = document.createElement("span");
        noteSpan.className = "meta note-text";
        noteSpan.dir = "auto";
        noteSpan.textContent = "📝 " + entry.note;
        li.appendChild(noteSpan);
      }
      li.appendChild(rowDeleteButton(entry));
      li.addEventListener("click", function () { navigateNote(entry.path); });
      notes.appendChild(li);
    });
  }

  function selectIndex(index) {
    var items = $$("#notes-list li");
    items.forEach(function (el, i) { el.classList.toggle("selected", i === index); });
    state.selectedIndex = index;
  }

  function levelIcon(level) {
    if (level === "secretfile") { return "🔑"; }
    if (level === "secret") { return "🔒"; }
    return "🔓";
  }

  function humanSize(n) {
    n = Number(n) || 0;
    if (n < 1024) { return n + " B"; }
    var units = ["KB", "MB", "GB", "TB"];
    var size = n;
    for (var i = 0; i < units.length; i += 1) {
      size /= 1024;
      if (size < 1024 || i === units.length - 1) { return size.toFixed(1) + " " + units[i]; }
    }
    return n + " B";
  }

  function formatDate(ms) {
    try {
      var date = new Date(Number(ms));
      var pad = function (n) { return (n < 10 ? "0" : "") + n; };
      return pad(date.getFullYear()) + "-" + pad(date.getMonth() + 1) + "-" +
        pad(date.getDate()) + " " + pad(date.getHours()) + ":" + pad(date.getMinutes());
    } catch (e) { return ""; }
  }

  function formatDateTime(ms) {
    try { return new Date(Number(ms)).toLocaleString(); } catch (e) { return ""; }
  }

  /* ----------------------------------------------------------- view panes */
  function showView(name) {
    ["welcome", "folder", "note", "edit", "search", "tag"].forEach(function (view) {
      var el = $("#view-" + view);
      if (el) { el.hidden = view !== name; }
    });
  }

  /* --------------------------------------------------------------- note */
  //: Extensions the browser can show directly (they must never be read as text).
  var IMAGE_RE = /\.(png|jpe?g|gif|webp|bmp|svg|avif|ico)$/i;
  //: Other binary files: offer them as a download, never as text.
  var BINARY_RE = /\.(pdf|zip|gz|tgz|tar|7z|rar|docx?|xlsx?|pptx?|odt|ods|odp|epub|mp3|wav|ogg|m4a|mp4|mkv|mov|webm|apk|exe|bin|iso|dmg)$/i;

  function isImagePath(path) {
    return IMAGE_RE.test(path || "");
  }

  function isBinaryPath(path) {
    return isImagePath(path) || BINARY_RE.test(path || "");
  }

  function showBinary(entry) {
    // A binary file is not text: reading it through vault.read_file made the server answer
    // "invalid request". Its bytes are served by /api/blob, so show them here instead.
    state.file = {
      path: entry.path,
      name: entry.path.split("/").pop(),
      sensitivity: entry.sensitivity || "normal",
      content: "",
      mtime: entry.mtime,
      created: entry.created || entry.mtime,
      tags: entry.tags || [],
      source_url: null,
      binary: true,
      image: isImagePath(entry.path)
    };
    state.dirty = false;
    state.editing = false;
    state.preview = false;
    renderNoteView();
    showView("note");
    refreshStatusBar();
  }

  function uniqueAttachmentName(name) {
    var stamp = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14);
    var base = String(name || "").split("/").pop() || "";
    if (!base) { return "pasted-" + stamp + ".png"; }
    return base;
  }

  function uploadImage(file) {
    // Paste/insert goes through the same write path the desktop uses: bytes are base64-encoded
    // and stored under /attachments, then the markdown reference is inserted at the caret.
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onerror = function () { reject(new Error("read_failed")); };
      reader.onload = function () {
        var dataUrl = String(reader.result || "");
        var comma = dataUrl.indexOf(",");
        var base64 = comma >= 0 ? dataUrl.slice(comma + 1) : "";
        if (!base64) { reject(new Error("empty_file")); return; }
        var path = "/attachments/" + uniqueAttachmentName(file && file.name);
        call("vault.write_file", { path: path, content: base64, encoding: "base64" })
          .then(function () { resolve(path); })
          .catch(reject);
      };
      reader.readAsDataURL(file);
    });
  }

  function insertAtCursor(snippet) {
    var editor = $("#editor");
    if (!editor) { return; }
    var start = editor.selectionStart === null ? editor.value.length : editor.selectionStart;
    var end = editor.selectionEnd === null ? start : editor.selectionEnd;
    var before = editor.value.slice(0, start);
    var after = editor.value.slice(end);
    var needsBreak = before && !/\n$/.test(before) ? "\n" : "";
    editor.value = before + needsBreak + snippet + after;
    var caret = before.length + needsBreak.length + snippet.length;
    editor.selectionStart = caret;
    editor.selectionEnd = caret;
    editor.focus();
    state.dirty = true;
    $("#dirty-indicator").hidden = false;
    updatePreview();
  }

  function insertImageFiles(files) {
    var images = Array.prototype.slice.call(files || []).filter(function (f) {
      return f && /^image\//.test(f.type || "");
    });
    if (!images.length) { return; }
    images.forEach(function (file) {
      uploadImage(file).then(function (path) {
        insertAtCursor("![" + path.split("/").pop() + "](vault:" + path + ")");
        showToast(t("web.image_inserted"), "ok");
      }).catch(function (err) {
        showToast(errorText(err), "error");
      });
    });
  }

  function askName(options) {
    var opts = options || {};
    return new Promise(function (resolve) {
      var modal = buildModal(opts.title || t("web.new_note"));
      openModal(modal.root);
      var input = document.createElement("input");
      input.type = "text";
      input.dir = "auto";
      input.placeholder = opts.placeholder || "";
      if (opts.value) { input.value = opts.value; }
      var hint = document.createElement("p");
      hint.className = "hint";
      hint.textContent = opts.hint || "";
      if (opts.hint) { modal.body.appendChild(hint); }
      modal.body.appendChild(input);
      var ok = document.createElement("button");
      ok.type = "button";
      ok.className = "primary";
      ok.textContent = opts.confirm || t("web.create");
      var cancel = document.createElement("button");
      cancel.type = "button";
      cancel.textContent = t("web.cancel");
      modal.actions.appendChild(cancel);
      modal.actions.appendChild(ok);
      function close(value) { modal.root.remove(); resolve(value); }
      function submit() {
        var value = input.value.trim();
        if (!value) {
          hint.className = "hint error";
          hint.textContent = t("web.name_required");
          input.focus();
          return;
        }
        close(value);
      }
      cancel.addEventListener("click", function () { close(""); });
      ok.addEventListener("click", submit);
      input.addEventListener("keydown", function (ev) {
        if (ev.key === "Enter") { ev.preventDefault(); submit(); }
        if (ev.key === "Escape") { close(""); }
      });
      window.setTimeout(function () { input.focus(); if (input.select) { input.select(); } }, 0);
    });
  }

  function currentFolder() {
    return state.cwd && state.cwd !== "/" ? state.cwd.replace(/\/+$/, "") : "";
  }

  function createNote(name) {
    if (!name) { return Promise.resolve(); }
    var safe = name.replace(/[\\:*?"<>|]/g, "-");
    if (!/\.[a-z0-9]{1,5}$/i.test(safe)) { safe += ".md"; }
    var folder = currentFolder();
    var path = folder + "/" + safe;
    var seed = "# " + name + "\n";
    return call("vault.write_file", { path: path, content: seed, sensitivity: "normal" })
      .then(function () {
        showToast(t("web.note_created"), "ok");
        // Refreshing the listing switches the centre view back to the folder, so the editor is
        // entered only after those loads settle.
        return Promise.all([loadIndex(), loadFolder(folder || "/")]);
      })
      .then(function () {
        state.file = {
          path: path, name: safe, sensitivity: "normal", content: seed,
          mtime: Date.now(), created: Date.now(), tags: [], source_url: null
        };
        enterEditMode();
      })
      .catch(function (err) {
        showToast(errorText(err), "error");
        throw err;
      });
  }

  function askNewNote() {
    return askName({
      title: t("web.new_note"),
      placeholder: t("dialog.new_note_prompt"),
      hint: t("web.new_note_hint")
    }).then(function (name) { return createNote(name); });
  }

  function createFolder(name) {
    if (!name) { return Promise.resolve(); }
    var safe = name.replace(/[\\:*?"<>|]/g, "-");
    var path = currentFolder() + "/" + safe;
    return call("vault.mkdir", { path: path })
      .then(function () {
        showToast(t("web.folder_created"), "ok");
        return Promise.all([loadIndex(), loadFolder(currentFolder() || "/")]);
      })
      .catch(function (err) {
        showToast(errorText(err), "error");
        throw err;
      });
  }

  function askNewFolder() {
    return askName({
      title: t("dialog.new_folder"),
      placeholder: t("dialog.new_folder_prompt"),
      hint: t("web.new_folder_hint")
    }).then(function (name) { return createFolder(name); });
  }

  function openFile(entry) {
    if (state.dirty && !window.confirm(t("editor.unsaved_text"))) { return; }
    if (entry.sensitivity === "secret" || entry.sensitivity === "secretfile") {
      openPlainViewer(entry.path);
      return;
    }
    if (isBinaryPath(entry.path)) {
      showBinary(entry);
      return Promise.resolve();
    }
    return call("vault.read_file", { path: entry.path }).then(function (result) {
      showNoteResult(result);
    }).catch(function (err) {
      if (err.code === "PERMISSION_DENIED" && err.details && err.details.requires_approval) {
        openPlainViewer(err.details.path || entry.path);
        return;
      }
      showToast(errorText(err), "error");
    });
  }

  function showNoteResult(result) {
    state.file = {
      path: result.path,
      name: result.path.split("/").pop(),
      sensitivity: result.sensitivity,
      content: result.content,
      mtime: result.mtime,
      created: result.created || result.mtime,
      tags: result.tags || [],
      note: result.note || "",
      source_url: result.source_url || null
    };
    state.dirty = false;
    state.editing = false;
    state.preview = false;
    renderNoteView();
    showView("note");
    refreshStatusBar();
  }

  function renderNoteView() {
    if (!state.file) { return; }
    renderBreadcrumbs($("#note-crumbs"), state.file.path, navigateFolder, { file: true });
    $("#note-title").textContent = state.file.name;
    $("#note-title").setAttribute("dir", "auto");
    var updated = formatDate(state.file.mtime);
    var created = formatDate(state.file.created || state.file.mtime);
    $("#note-meta").textContent =
      "📅 " + t("web.updated_at") + " " + updated + " · 🕓 " + t("web.created_at") + " " + created;
    var fileNote = $("#file-note-input");
    if (fileNote) { fileNote.value = state.file.note || ""; }
    var sourceLink = $("#note-source");
    if (sourceLink) {
      if (state.file.source_url) {
        sourceLink.hidden = false;
        sourceLink.textContent = "🔗 " + t("web.source_link");
        sourceLink.href = state.file.source_url;
      } else {
        sourceLink.hidden = true;
        sourceLink.removeAttribute("href");
      }
    }
    var tagBox = $("#note-tags");
    tagBox.textContent = "";
    (state.file.tags || []).forEach(function (tag) {
      var chip = document.createElement("button");
      chip.type = "button";
      chip.className = "chip";
      chip.dir = "auto";
      chip.textContent = tag;
      chip.addEventListener("click", function () { openTag(tag); });
      tagBox.appendChild(chip);
    });
    var body = $("#note-body");
    if (state.file.binary) {
      body.textContent = "";
      var node;
      if (state.file.image) {
        node = document.createElement("img");
        node.className = "binary-preview";
        node.alt = state.file.name;
        node.setAttribute("data-blob-src", state.file.path);
      } else {
        node = document.createElement("p");
        node.className = "broken-image";
        node.textContent = "📦 " + state.file.name;
      }
      body.appendChild(node);
      hydrateImages(body);
    } else if (state.file.sensitivity === "normal") {
      body.innerHTML = renderMarkdown(state.file.content, state.file.path);
      hydrateImages(body);
    } else {
      body.textContent = t("web.preview_disabled");
    }
    // Editing or showing the raw text makes no sense for a binary file.
    //: Note actions live above the title only (the bottom row was removed on request).
    ["#btn-note-edit-top", "#btn-note-raw-top"].forEach(function (selector) {
      var button = $(selector);
      if (button) { button.hidden = !!state.file.binary; }
    });
    $("#level-select").value = state.file.sensitivity;
    $("#level-select").hidden = false;
  }

  function openPlainViewer(path) {
    if (!window.confirm(t("web.secretfile_confirm"))) { return; }
    call("vault.read_secret", { path: path }).then(function (result) {
      showPlainModal(result.path, result.content);
    }).catch(function (err) { showToast(errorText(err), "error"); });
  }

  function showPlainModal(path, content) {
    var modal = buildModal(t("viewer.title"));
    var pre = document.createElement("pre");
    pre.className = "plain";
    pre.setAttribute("dir", "ltr");
    pre.textContent = content;
    modal.body.appendChild(pre);
    var copy = document.createElement("button");
    copy.type = "button";
    copy.textContent = t("viewer.copy");
    copy.addEventListener("click", function () {
      if (navigator.clipboard) { navigator.clipboard.writeText(content); }
      showToast(t("notification.copied"), "ok");
    });
    modal.actions.appendChild(copy);
    addCloseButton(modal);
    openModal(modal.root);
  }

  /* --------------------------------------------------------------- editor */
  function enterEditMode() {
    if (!state.file || state.file.sensitivity === "secretfile" || state.file.binary) { return; }
    state.editing = true;
    $("#editor").value = state.file.content;
    $("#editor-path").textContent = state.file.path;
    $("#level-select").value = state.file.sensitivity;
    $("#level-select").hidden = false;
    $("#dirty-indicator").hidden = true;
    state.dirty = false;
    state.preview = false;
    $("#preview").hidden = true;
    showView("edit");
    $("#editor").focus();
  }

  function cancelEdit() {
    if (state.dirty && !window.confirm(t("editor.unsaved_text"))) { return; }
    state.dirty = false;
    state.editing = false;
    if (state.file) { renderNoteView(); showView("note"); }
    else { showView("welcome"); }
  }

  function saveFile() {
    if (!state.file || state.dirty === false) { return; }
    pushBusy();
    call("vault.write_file", { path: state.file.path, content: $("#editor").value }).then(function () {
      state.file.content = $("#editor").value;
      state.dirty = false;
      $("#dirty-indicator").hidden = true;
      showToast(t("web.saved"), "ok");
      loadIndex();
      renderNoteView();
      showView("note");
      state.editing = false;
    }).catch(function (err) { showToast(errorText(err), "error"); }).then(popBusy);
  }

  function updatePreview() {
    var preview = $("#preview");
    if (!state.preview || !state.file || state.file.sensitivity !== "normal") {
      preview.hidden = true;
      return;
    }
    preview.hidden = false;
    preview.innerHTML = renderMarkdown($("#editor").value, state.file.path);
    hydrateImages(preview);
  }

  function applyFormat(action) {
    var area = $("#editor");
    var start = area.selectionStart;
    var end = area.selectionEnd;
    var value = area.value;
    var selected = value.slice(start, end);
    var before = value.slice(0, start);
    var after = value.slice(end);
    var replacements = {
      bold: ["**", "**", "text"],
      italic: ["*", "*", "text"],
      strike: ["~~", "~~", "text"],
      code: ["`", "`", "code"],
      heading: ["## ", "", "heading"],
      quote: ["> ", "", "quote"],
      ul: ["- ", "", "item"],
      ol: ["1. ", "", "item"],
      link: ["[", "](path)", "label"],
      image: ["![", "](path)", "alt"],
      hr: ["\n---\n", "", ""]
    };
    var spec = replacements[action];
    if (!spec) { return; }
    var text = selected || spec[2];
    var insert = spec[0] + text + spec[1];
    area.value = before + insert + after;
    area.focus();
    var caret = start + spec[0].length + text.length;
    area.setSelectionRange(caret, caret);
    area.dispatchEvent(new Event("input"));
  }

  function buildFormatToolbar() {
    var bar = $("#format-toolbar");
    if (!bar) { return; }
    bar.textContent = "";
    TOOLBAR_ACTIONS.forEach(function (pair) {
      var button = document.createElement("button");
      button.type = "button";
      button.className = "format-btn";
      button.dataset.action = pair[0];
      button.textContent = pair[1];
      button.title = t("web.action_" + pair[0]);
      button.setAttribute("aria-label", button.title);
      if (pair[0] === "image") {
        // The toolbar's image button uploads a file (/attachments) instead of inserting an empty
        // ![]() placeholder; pasting into the editor does the same thing.
        button.addEventListener("click", function () {
          var input = $("#image-input");
          if (input) { input.click(); }
        });
      } else {
        button.addEventListener("click", function () { applyFormat(pair[0]); });
      }
      bar.appendChild(button);
    });
  }

  /* ------------------------------------------------------------- markdown */
  function showStaleBanner() {
    var banner = $("#stale-banner");
    if (!banner || !banner.hidden) { return; }
    banner.textContent = t("web.stale_tab");
    banner.hidden = false;
  }

  function escapeHtml(text) {
    return String(text).replace(/[&<>"']/g, function (ch) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch];
    });
  }

  function unescapeHtml(text) {
    // The inverse of escapeHtml: inlineMarkdown and every path helper work on decoded text.
    return String(text == null ? "" : text)
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .replace(/&amp;/g, "&");
  }

  function stripWrappers(src) {
    // Markdown allows <...> around a path, and quotes sneak in from exports.
    // renderMarkdown escapes the body *before* inlineMarkdown runs, so a mirror-style reference
    // arrives as "&lt;../../x.jpg&gt;" — decode first, or the brackets (and the trailing "&gt;")
    // defeat every path lookup below.
    var out = unescapeHtml(src == null ? "" : String(src)).trim();
    if (out.length > 2 && out.charAt(0) === "<" && out.charAt(out.length - 1) === ">") {
      out = out.slice(1, -1).trim();
    }
    if (out.length > 1 && (out.charAt(0) === '"' || out.charAt(0) === "'") &&
        out.charAt(out.length - 1) === out.charAt(0)) {
      out = out.slice(1, -1).trim();
    }
    return out;
  }

  function collapseDots(path) {
    // "../../x" must not survive: the vault has no such folders (Joplin exports them relative
    // to the mirror's assets directory).
    var parts = String(path || "").split("/");
    var out = [];
    parts.forEach(function (part) {
      if (!part || part === ".") { return; }
      if (part === "..") { out.pop(); return; }
      out.push(part);
    });
    return "/" + out.join("/");
  }

  function basename(path) {
    var parts = String(path || "").split("/");
    return parts[parts.length - 1] || "";
  }

  function resolveVaultPath(notePath, src) {
    var raw = stripWrappers(src);
    if (raw.indexOf("vault:/") === 0) { return collapseDots(raw.slice("vault:/".length)); }
    if (raw.charAt(0) === "/") { return collapseDots(raw); }
    var base = notePath ? notePath.split("/").slice(0, -1).join("/") : "";
    return collapseDots((base ? base : "") + "/" + raw);
  }

  function attachmentFallback(path) {
    // Every imported resource lives in /attachments/<file>; a relative or bare reference to an
    // asset folder therefore still finds its file. The reference may arrive wrapped in angle
    // brackets (mirror style: ``![x](<../../assets/x.jpg>)``) — strip those first, otherwise the
    // resulting name keeps the trailing ``>`` and never resolves.
    var clean = stripWrappers(path);
    var name = basename(clean);
    if (!name || !/\.[a-z0-9]{1,6}$/i.test(name)) { return ""; }
    return name.indexOf("/attachments/") !== 0 ? "/attachments/" + name : "";
  }

  var MEDIA_KIND = [
    [/\.(png|jpe?g|gif|webp|bmp|svg|avif|ico)$/i, "image"],
    [/\.(mp3|wav|ogg|m4a|flac|aac)$/i, "audio"],
    [/\.(mp4|mkv|mov|webm|avi)$/i, "video"],
    [/\.pdf$/i, "pdf"]
  ];

  function mediaKind(path) {
    for (var i = 0; i < MEDIA_KIND.length; i++) {
      if (MEDIA_KIND[i][0].test(path || "")) { return MEDIA_KIND[i][1]; }
    }
    return "";
  }

  function mediaNode(kind, path, label) {
    if (kind === "image") {
      if (/^data:/i.test(path)) {
        // Never pass a data URI to /api/blob (the URL becomes megabytes long) or keep it as a
        // src attribute: hydrateImages() turns it into a Blob and an object URL.
        return '<img alt="' + escapeHtml(label) + '" data-uri-src="' + escapeHtml(path) + '">';
      }
      return '<img alt="' + escapeHtml(label) + '" data-blob-src="' + escapeHtml(path) +
        '" data-blob-fallback="' + escapeHtml(attachmentFallback(path)) + '">';
    }
    if (kind === "audio" || kind === "video") {
      // The player is filled once the bytes arrive (hydrateMedia).
      return '<' + kind + ' controls preload="none" data-blob-src="' + escapeHtml(path) +
        '" data-blob-fallback="' + escapeHtml(attachmentFallback(path)) + '"></' + kind + '>';
    }
    if (kind === "pdf") {
      return '<a class="file-card" data-blob-src="' + escapeHtml(path) +
        '" data-blob-fallback="' + escapeHtml(attachmentFallback(path)) +
        '" target="_blank" rel="noopener noreferrer">📄 ' + escapeHtml(label) + '</a>';
    }
    return '<a class="file-card" data-blob-src="' + escapeHtml(path) + '" data-blob-fallback="' +
      escapeHtml(attachmentFallback(path)) + '" download>📎 ' + escapeHtml(label) + '</a>';
  }

  function inlineMarkdown(text, notePath) {
    text = text.replace(/`([^`]+)`/g, "<code dir=\"ltr\">$1</code>");
    text = text.replace(/~~([^~]+)~~/g, "<del>$1</del>");
    text = text.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    text = text.replace(/\*([^*]+)\*/g, "<em>$1</em>");
    text = text.replace(/!\[([^\]]*)\]\(([^)]+)\)/g, function (m, alt, src) {
      var raw = src.trim();
      if (/^data:/i.test(raw)) {
        // Already inline: decode it in the browser (hydrateImages). Putting the URI straight into
        // src broke whenever it was wrapped over several lines, and /api/blob just got an
        // enormous URL back as "invalid request".
        return '<img alt="' + escapeHtml(alt) + '" data-uri-src="' + escapeHtml(raw) + '">';
      }
      if (/^(https?:)?\/\//i.test(raw)) {
        // Never fetch the network from the vault UI; show what the note referenced instead.
        return '<span class="broken-image" title="' + escapeHtml(raw) + '">🖼 ' +
          escapeHtml(alt || raw) + '</span>';
      }
      var resolved = resolveVaultPath(notePath, raw);
      return mediaNode(mediaKind(resolved) || "image", resolved, alt);
    });
    text = text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, function (m, label, href) {
      var linkKind = mediaKind(stripWrappers(href));
      if (linkKind) {
        // A link to a file that the browser can show becomes an inline player/preview.
        return mediaNode(linkKind, resolveVaultPath(notePath, href), label);
      }
      var target = href.trim();
      if (target.indexOf("vault:/") === 0 || (target.charAt(0) === "/" && !/^\/\//.test(target))) {
        var path = target.indexOf("vault:/") === 0 ? target.slice("vault:/".length) : target.slice(1);
        return '<a href="#/note/' + encodeURI(path) + '">' + label + "</a>";
      }
      if (target.charAt(0) === "#") { return '<a href="' + target + '">' + label + "</a>"; }
      return '<a href="' + target + '" target="_blank" rel="noopener noreferrer">' + label + "</a>";
    });
    return text;
  }

  function renderMarkdown(source, notePath) {
    // Bodies exported from Joplin contain raw <img src="data:..."> HTML; escaping it showed the
    // markup as text. Turn those tags into markdown images first, then escape everything else.
    source = String(source || "").replace(/<img[^>]*?\bsrc\s*=\s*["'](data:[^"']*)["'][^>]*>/gi,
      function (m, src) { return "![](" + src.replace(/\s+/g, "") + ")"; });
    source = source.replace(/<img[^>]*?\bsrc\s*=\s*["']?([^"'>\s]+)["']?[^>]*>/gi,
      function (m, src) { return "![](" + src.trim() + ")"; });
    var lines = escapeHtml(source).split(/\r?\n/);
    var html = [];
    var inCode = false;
    var inList = null;
    var inQuote = false;
    var inTable = false;
    function closeList() { if (inList) { html.push("</" + inList + ">"); inList = null; } }
    function closeQuote() { if (inQuote) { html.push("</blockquote>"); inQuote = false; } }
    function closeTable() { if (inTable) { html.push("</tbody></table>"); inTable = false; } }
    function openList(kind) {
      if (inList !== kind) { closeList(); html.push("<" + kind + ">"); inList = kind; }
    }
    lines.forEach(function (line) {
      if (/^```/.test(line)) {
        if (inCode) { html.push("</code></pre>"); inCode = false; }
        else { closeList(); closeQuote(); closeTable(); html.push('<pre><code dir="ltr">'); inCode = true; }
        return;
      }
      if (inCode) { html.push(line); return; }
      if (/^\s*(-{3,}|\*{3,}|_{3,})\s*$/.test(line)) {
        closeList(); closeQuote(); closeTable(); html.push("<hr>"); return;
      }
      var heading = /^(#{1,6})\s+(.*)$/.exec(line);
      if (heading) {
        closeList(); closeQuote(); closeTable();
        var level = heading[1].length;
        html.push("<h" + level + ' dir="auto">' + inlineMarkdown(heading[2], notePath) + "</h" + level + ">");
        return;
      }
      var task = /^\s*[-*+]\s+\[([ xX])\]\s+(.*)$/.exec(line);
      if (task) {
        closeQuote(); closeTable(); openList("ul");
        var done = task[1].toLowerCase() === "x";
        html.push('<li class="task' + (done ? " done" : "") + '"><input type="checkbox" disabled' +
          (done ? " checked" : "") + "> " + inlineMarkdown(task[2], notePath) + "</li>");
        return;
      }
      if (/^\s*[-*+]\s+/.test(line)) {
        closeQuote(); closeTable(); openList("ul");
        html.push("<li>" + inlineMarkdown(line.replace(/^\s*[-*+]\s+/, ""), notePath) + "</li>");
        return;
      }
      if (/^\s*\d+\.\s+/.test(line)) {
        closeQuote(); closeTable(); openList("ol");
        html.push("<li>" + inlineMarkdown(line.replace(/^\s*\d+\.\s+/, ""), notePath) + "</li>");
        return;
      }
      if (/^\s*>\s?/.test(line)) {
        closeList(); closeTable();
        if (!inQuote) { html.push("<blockquote>"); inQuote = true; }
        html.push("<p>" + inlineMarkdown(line.replace(/^\s*>\s?/, ""), notePath) + "</p>");
        return;
      }
      if (/\|/.test(line) && /^\s*\|?.*\|/.test(line)) {
        closeList(); closeQuote();
        var cells = line.split("|").map(function (c) { return c.trim(); }).filter(function (c) { return c !== ""; });
        if (cells.length && /^:?-+:?$/.test(cells[0].replace(/\s/g, ""))) { return; }
        if (!inTable) { html.push("<table><tbody>"); inTable = true; }
        html.push("<tr>" + cells.map(function (c) { return "<td>" + inlineMarkdown(c, notePath) + "</td>"; }).join("") + "</tr>");
        return;
      }
      closeList(); closeQuote(); closeTable();
      if (line.trim() === "") { return; }
      html.push('<p dir="auto">' + inlineMarkdown(line, notePath) + "</p>");
    });
    closeList(); closeQuote(); closeTable();
    if (inCode) { html.push("</code></pre>"); }
    return html.join("\n");
  }

  function brokenImageNode(label) {
    var span = document.createElement("span");
    span.className = "broken-image";
    span.textContent = "🖼 " + (label || "?");
    return span;
  }

  function fetchBlob(path, fallback) {
    // One retry against /attachments/<name>: Joplin bodies point at the mirror's assets folder.
    return request("GET", "/api/blob?path=" + encodeURIComponent(path), { raw: true })
      .then(function (r) {
        if (r.ok) { return r.response.blob(); }
        if (!fallback) { return null; }
        return request("GET", "/api/blob?path=" + encodeURIComponent(fallback), { raw: true })
          .then(function (r2) { return r2.ok ? r2.response.blob() : null; });
      })
      .catch(function () { return null; });
  }

  function dataUriToBlob(uri) {
    // "data:image/png;base64,AAAA" -> Blob. Whitespace inside the payload is ignored, which is
    // what Joplin-exported bodies need (their base64 is wrapped across lines).
    var match = /^data:([^;,]*)((?:;[^,]*)*),([\s\S]*)$/.exec(uri);
    if (!match) { return null; }
    var mime = match[1] || "image/png";
    var params = match[2] || "";
    var payload = match[3] || "";
    var bytes;
    if (/;base64/i.test(params)) {
      var clean = payload.replace(/[^A-Za-z0-9+/=]/g, "");
      if (!clean) { return null; }
      var binary = window.atob(clean);
      bytes = new Uint8Array(binary.length);
      for (var i = 0; i < binary.length; i += 1) { bytes[i] = binary.charCodeAt(i); }
    } else {
      bytes = new TextEncoder().encode(decodeURIComponent(payload));
    }
    return new Blob([bytes], { type: mime });
  }

  function hydrateImages(root) {
    $$("[data-uri-src]", root).forEach(function (node) {
      var uri = node.getAttribute("data-uri-src") || "";
      var blob = null;
      try { blob = dataUriToBlob(uri); } catch (err) { blob = null; }
      if (!blob) {
        node.replaceWith(brokenImageNode(node.getAttribute("alt") || "image"));
        return;
      }
      node.src = URL.createObjectURL(blob);
      node.removeAttribute("data-uri-src");
    });
    $$("[data-blob-src]", root).forEach(function (node) {
      var path = node.getAttribute("data-blob-src");
      if (!path) { return; }
      var fallback = node.getAttribute("data-blob-fallback") || "";
      fetchBlob(path, fallback).then(function (blob) {
        if (!blob) {
          if (node.tagName === "IMG") {
            node.replaceWith(brokenImageNode(node.getAttribute("alt") || path));
          } else {
            node.classList.add("missing");
            node.setAttribute("title", path);
          }
          return;
        }
        var url = URL.createObjectURL(blob);
        if (node.tagName === "IMG" || node.tagName === "AUDIO" || node.tagName === "VIDEO") {
          node.src = url;
        } else if (node.tagName === "A") {
          node.href = url;
          var name = path.split("/").pop();
          node.appendChild(document.createTextNode(" " + name));
        }
        node.removeAttribute("data-blob-src");
        node.removeAttribute("data-blob-fallback");
      });
    });
  }

  /* --------------------------------------------------------- sensitivity */
  function changeLevel(level) {
    if (!state.file) { return; }
    var current = state.file.sensitivity;
    if (level === current) { return; }
    if (rank(level) < rank(current) && !window.confirm(t("dialog.lower_level_text", { path: state.file.path, level: t("level." + level) }))) {
      $("#level-select").value = current;
      return;
    }
    call("vault.set_sensitivity", { path: state.file.path, level: level }).then(function () {
      state.file.sensitivity = level;
      if (level !== "normal") { state.preview = false; }
      renderNoteView();
      showToast(t("web.level_changed", { level: t("level." + level) }), "ok");
      loadIndex();
    }).catch(function (err) {
      $("#level-select").value = current;
      showToast(errorText(err), "error");
    });
  }

  function rank(level) {
    return level === "secretfile" ? 2 : (level === "secret" ? 1 : 0);
  }

  /* ------------------------------------------------------------- actions */
  function newNote() {
    return askNewNote();
  }

  function newFolder() {
    return askNewFolder();
  }

  function renameEntry(entry) {
    askName({
      title: t("dialog.rename"),
      placeholder: t("dialog.rename_prompt"),
      value: entry.name,
      confirm: t("web.save")
    }).then(function (name) {
      if (!name || name === entry.name) { return; }
      var parent = entry.path.split("/").slice(0, -1).join("/");
      var dst = (parent ? parent : "") + "/" + name;
      return call("vault.file_ops", { op: "move", src: entry.path, dst: dst }).then(function () {
        showToast(t("web.renamed"), "ok");
        return Promise.all([loadIndex(), loadFolder(state.cwd)]);
      });
    }).catch(function (err) { showToast(errorText(err), "error"); });
  }

  function confirmDialog(message, confirmLabel) {
    return new Promise(function (resolve) {
      var modal = buildModal(message);
      openModal(modal.root);
      var cancel = document.createElement("button");
      cancel.type = "button";
      cancel.textContent = t("web.cancel");
      var ok = document.createElement("button");
      ok.type = "button";
      ok.className = "primary danger";
      ok.textContent = confirmLabel || t("menu.delete");
      modal.actions.appendChild(cancel);
      modal.actions.appendChild(ok);
      function close(value) { modal.root.remove(); resolve(value); }
      cancel.addEventListener("click", function () { close(false); });
      ok.addEventListener("click", function () { close(true); });
      window.setTimeout(function () { ok.focus(); }, 0);
    });
  }

  function performDelete(entry) {
    var isDir = !!entry.is_dir;
    var wasOpen = !!(state.file && state.file.path === entry.path);
    return call("vault.file_ops", {
      op: "delete", src: entry.path, recursive: isDir
    }).then(function (result) {
      showToast(t("web.deleted_n", { count: (result && result.affected) || 1 }), "ok");
      if (wasOpen) { state.file = null; }
      var target = isDir && state.cwd && state.cwd.indexOf(entry.path) === 0 ? "/" : state.cwd;
      // loadFolder() ends with showView("folder"); the welcome view is restored afterwards when
      // the note that was open is the one that just disappeared.
      return Promise.all([loadIndex(), loadFolder(target)]).then(function () {
        if (wasOpen) { showView("welcome"); }
      });
    }).catch(function (err) { showToast(errorText(err), "error"); });
  }

  function deleteEntry(entry) {
    if (!entry || !entry.path) { return Promise.resolve(); }
    return confirmDialog(t("dialog.delete_confirm", { path: entry.path }), t("menu.delete"))
      .then(function (ok) { if (ok) { return performDelete(entry); } });
  }

  function editTags(entry) {
    var value = window.prompt(t("dialog.tags_prompt"), (entry.tags || []).join(", "));
    if (value === null) { return; }
    var tags = value.split(",").map(function (s) { return s.trim(); }).filter(function (s) { return s; });
    call("vault.set_tags", { path: entry.path, tags: tags }).then(function () {
      showToast(t("web.tags_updated"), "ok");
      loadIndex();
    }).catch(function (err) { showToast(errorText(err), "error"); });
  }

  function showContextMenu(x, y, entry) {
    closeContextMenu();
    var menu = document.createElement("div");
    menu.className = "context-menu";
    menu.style.insetInlineStart = x + "px";
    menu.style.top = y + "px";
    function item(label, handler) {
      var button = document.createElement("button");
      button.type = "button";
      button.textContent = label;
      button.addEventListener("click", function () { closeContextMenu(); handler(); });
      menu.appendChild(button);
    }
    item(t("menu.open"), function () { navigateNote(entry.path); });
    if (entry.sensitivity === "secretfile") {
      item(t("menu.open_native"), function () { openPlainViewer(entry.path); });
    }
    item(t("menu.rename"), function () { renameEntry(entry); });
    item(t("menu.delete"), function () { deleteEntry(entry); });
    item(t("menu.copy_path"), function () { copyPath(entry.path); });
    var hr = document.createElement("hr");
    menu.appendChild(hr);
    ["normal", "secret", "secretfile"].forEach(function (level) {
      item(t("menu.set_level") + ": " + t("level." + level), function () {
        state.file = { path: entry.path, name: entry.name, sensitivity: entry.sensitivity, content: "" };
        changeLevel(level);
      });
    });
    item(t("menu.tags"), function () { editTags(entry); });
    document.body.appendChild(menu);
  }

  function closeContextMenu() { $$(".context-menu").forEach(function (el) { el.remove(); }); }

  function copyPath(path) {
    if (navigator.clipboard) { navigator.clipboard.writeText(path); }
    showToast(t("notification.copied"), "ok");
  }

  /* --------------------------------------------------------------- search */
  function runSearch() {
    var query = $("#global-search").value.trim();
    if (!query) { return; }
    var method = {
      filenames: "vault.search_filenames",
      text: "vault.search_text",
      semantic: "vault.search_semantic"
    }[state.searchKind];
    $("#search-crumbs").textContent = t("web.search_all") + ": " + query;
    $("#search-heading").textContent = t("web.search_heading");
    pushBusy();
    call(method, { query: query, limit: 50 }).then(function (result) {
      renderSearchResults(result.results || []);
      $("#search-status").textContent = t("web.results_count", { count: result.count || 0 });
      showView("search");
    }).catch(function (err) {
      $("#search-status").textContent = err.code === "PROVIDER_UNAVAILABLE"
        ? t("search.semantic_unavailable", { reason: (err.details && err.details.reason) || "" })
        : errorText(err);
      $("#global-results").textContent = "";
      showView("search");
    }).then(popBusy);
  }

  function renderSearchResults(results) {
    var list = $("#global-results");
    list.textContent = "";
    results.forEach(function (hit) {
      var li = document.createElement("li");
      var title = document.createElement("span");
      var path = hit.logical_path || hit.path || "";
      title.dir = "auto";
      title.textContent = path;
      li.appendChild(title);
      if (hit.snippet) {
        var snippet = document.createElement("span");
        snippet.className = "snippet";
        snippet.dir = "auto";
        snippet.textContent = hit.snippet;
        li.appendChild(snippet);
      }
      li.addEventListener("click", function () { navigateNote("/" + path.replace(/^\//, "")); });
      list.appendChild(li);
    });
  }

  /* -------------------------------------------------------------- activity */
  function addActivity(event) {
    state.activity.unshift(event);
    if (state.activity.length > 200) { state.activity.pop(); }
    updateActivityBanner(event);
  }

  function updateActivityBanner(event) {
    var banner = $("#activity-banner");
    if (!banner || !event || !event.kind) { return; }
    var path = event.path ? "/" + String(event.path).replace(/^\//, "") : "";
    if (event.kind === "read" && path) {
      banner.textContent = t("web.activity_now", { path: path, source: event.source || "" });
    } else if (event.kind === "list" && path) {
      banner.textContent = t("web.activity_now_list", { path: path, source: event.source || "" });
    } else if (event.kind === "search") {
      banner.textContent = t("web.activity_now_search", { source: event.source || "" });
    } else {
      return;
    }
    banner.hidden = false;
    if (banner._hideTimer) { window.clearTimeout(banner._hideTimer); }
    banner._hideTimer = window.setTimeout(function () { banner.hidden = true; }, 4000);
  }

  /* -------------------------------------------------------------- settings */
  /* --------------------------------------------------------- status / SSE */
  function refreshStatusBar() {
    var locked = state.session ? !!state.session.locked : true;
    var counts = state.session && state.session.counts;
    var files = counts ? counts.files : ((state.index.counts && state.index.counts.files) || 0);
    statusBase = (locked ? t("status.locked") : t("status.unlocked")) + " · " +
      t("status.files", { count: files }) + " · " + t("status.mcp", { count: 0 });
    $("#foot-lock").textContent = locked ? t("status.locked") : t("status.unlocked");
    $("#foot-files").textContent = t("status.files", { count: files });
    $("#foot-agents").textContent = t("status.mcp", { count: 0 });
    updateAutoLockLabel();
  }

  function autoLockText() {
    var seconds = state.session ? state.session.auto_lock_seconds : 0;
    if (!seconds) { return t("web.auto_lock_off"); }
    var elapsed = Math.floor((Date.now() - state.lastActivity) / 1000);
    return t("web.auto_lock", { seconds: Math.max(0, seconds - elapsed) });
  }

  function updateAutoLockLabel() {
    var auto = autoLockText();
    $("#foot-autolock").textContent = auto;
    var statusEl = $("#status-text");
    if (statusBase && statusEl) { statusEl.textContent = statusBase + " · " + auto; }
  }

  function startAutoLock() { window.setInterval(updateAutoLockLabel, 1000); }

  function connectEvents() {
    if (state.eventAbort) { state.eventAbort.abort(); }
    var controller = new AbortController();
    state.eventAbort = controller;
    fetch("/api/events", {
      headers: { "X-Vault-Token": state.token },
      signal: controller.signal
    }).then(function (res) {
      if (!res.ok || !res.body) { throw new Error("sse"); }
      var reader = res.body.getReader();
      var decoder = new TextDecoder();
      var buffer = "";
      function pump() {
        return reader.read().then(function (chunk) {
          if (chunk.done) { return; }
          buffer += decoder.decode(chunk.value, { stream: true });
          var index;
          while ((index = buffer.indexOf("\n\n")) >= 0) {
            var frame = buffer.slice(0, index);
            buffer = buffer.slice(index + 2);
            frame.split("\n").forEach(function (line) {
              if (line.indexOf("data:") === 0) {
                try { handleEvent(JSON.parse(line.slice(5).trim())); } catch (e) { /* ignore */ }
              }
            });
          }
          return pump();
        });
      }
      return pump();
    }).catch(function () {
      if (!controller.signal.aborted) {
        showToast(t("web.connection_lost"), "warn");
        window.setTimeout(connectEvents, 3000);
      }
    });
  }

  function handleEvent(event) {
    if (!event || !event.event) { return; }
    if (event.event === "log") {
      // the web UI has no log panel; the tray and the desktop app own that view
    } else if (event.event === "data_changed") {
      loadIndex();
    } else if (event.event === "lock") {
      handleLockEvent();
    } else if (event.event === "unlock") {
      loadSession().then(refreshStatusBar);
    } else if (event.event === "secret_request") {
      showSecretRequest(event);
    } else if (event.event === "activity") {
      addActivity(event);
    }
  }

  function handleLockEvent() {
    state.session = state.session || {};
    state.session.locked = true;
    state.session.counts = null;
    state.file = null;
    state.dirty = false;
    state.index = { tree: [], tags: [], counts: {} };
    $("#folder-tree").textContent = "";
    $("#tag-chips").textContent = "";
    $("#global-results").textContent = "";
    state.activity = [];
    var banner = $("#activity-banner");
    if (banner) { banner.hidden = true; }
    closeAllModals();
    showLogin("");
    showToast(t("status.locked"), "warn");
  }

  function showSecretRequest(event) {
    var modal = buildModal(t("request.title"));
    var message = document.createElement("p");
    message.dir = "auto";
    message.textContent = t("request.message", { path: event.path || "" });
    modal.body.appendChild(message);
    var show = document.createElement("button");
    show.type = "button";
    show.className = "primary";
    show.textContent = t("request.show");
    show.addEventListener("click", function () {
      call("vault.read_secret", { path: event.path }).then(function (result) {
        showPlainModal(result.path, result.content);
        return call("vault.resolve_open_secret", { request_id: event.request_id, approved: true });
      }).catch(function (err) { showToast(errorText(err), "error"); });
      closeModal(modal.root);
    });
    var deny = document.createElement("button");
    deny.type = "button";
    deny.textContent = t("request.deny");
    deny.addEventListener("click", function () {
      call("vault.resolve_open_secret", { request_id: event.request_id, approved: false })
        .catch(function (err) { showToast(errorText(err), "error"); });
      closeModal(modal.root);
    });
    modal.actions.appendChild(show);
    modal.actions.appendChild(deny);
    openModal(modal.root);
  }

  /* -------------------------------------------------------------- modals */
  function buildModal(title) {
    var root = document.createElement("div");
    root.className = "modal-backdrop";
    var box = document.createElement("div");
    box.className = "modal";
    var heading = document.createElement("h2");
    heading.textContent = title;
    var body = document.createElement("div");
    var actions = document.createElement("div");
    actions.className = "actions";
    box.appendChild(heading);
    box.appendChild(body);
    box.appendChild(actions);
    root.appendChild(box);
    root.addEventListener("click", function (ev) { if (ev.target === root) { closeModal(root); } });
    return { root: root, body: body, actions: actions };
  }

  function addCloseButton(modal) {
    var close = document.createElement("button");
    close.type = "button";
    close.textContent = t("web.close");
    close.addEventListener("click", function () { closeModal(modal.root); });
    modal.actions.appendChild(close);
  }

  function openModal(root) { $("#modal-root").appendChild(root); }
  function closeModal(root) { if (root && root.parentNode) { root.parentNode.removeChild(root); } }
  function closeAllModals() { $("#modal-root").textContent = ""; }

  function addDiffLine(pre, text, cls) {
    var span = document.createElement("span");
    span.className = "diff-" + cls;
    span.textContent = text + "\n";
    pre.appendChild(span);
  }

  function showVersionDiff(path, fromVersion, toVersion, pre) {
    return call("vault.diff", {
      path: path,
      from_version: Number(fromVersion),
      to_version: Number(toVersion)
    }).then(function (result) {
      pre.textContent = "";
      (result.hunks || []).forEach(function (hunk) {
        if (hunk.type === "delete" || hunk.type === "replace") {
          hunk.a_lines.forEach(function (line) { addDiffLine(pre, "- " + line, "del"); });
        }
        if (hunk.type === "insert" || hunk.type === "replace") {
          hunk.b_lines.forEach(function (line) { addDiffLine(pre, "+ " + line, "add"); });
        }
        if (hunk.type === "equal") {
          hunk.a_lines.forEach(function (line) { addDiffLine(pre, "  " + line, "ctx"); });
        }
      });
      if (!pre.textContent) { pre.textContent = t("versions.no_changes"); }
    }).catch(function (err) { pre.textContent = errorText(err); });
  }

  function openVersions(path) {
    call("vault.versions", { path: path }).then(function (result) {
      var versions = result.versions || [];
      var modal = buildModal(t("versions.title"));
      var heading = document.createElement("p");
      heading.className = "muted";
      heading.textContent = t("versions.heading", { path: path });
      modal.body.appendChild(heading);
      var table = document.createElement("table");
      table.className = "versions-table";
      versions.forEach(function (version) {
        var row = document.createElement("tr");
        [String(version.version), formatDate(version.mtime),
         humanSize(version.size), String(version.source)].forEach(function (cell) {
          var td = document.createElement("td");
          td.textContent = cell;
          row.appendChild(td);
        });
        table.appendChild(row);
      });
      modal.body.appendChild(table);
      var picker = document.createElement("div");
      picker.className = "versions-picker";
      var fromSel = document.createElement("select");
      var toSel = document.createElement("select");
      versions.forEach(function (version) {
        fromSel.appendChild(new Option(String(version.version), version.version));
        toSel.appendChild(new Option(String(version.version), version.version));
      });
      if (versions.length) {
        fromSel.selectedIndex = Math.min(1, versions.length - 1);
        toSel.selectedIndex = 0;
      }
      var showBtn = document.createElement("button");
      showBtn.type = "button";
      showBtn.textContent = t("versions.show_diff");
      var pre = document.createElement("pre");
      pre.className = "diff-view";
      showBtn.addEventListener("click", function () {
        showVersionDiff(path, fromSel.value, toSel.value, pre);
      });
      picker.appendChild(fromSel);
      picker.appendChild(toSel);
      picker.appendChild(showBtn);
      modal.body.appendChild(picker);
      modal.body.appendChild(pre);
      addCloseButton(modal);
      openModal(modal.root);
      if (versions.length >= 2) {
        showVersionDiff(path, fromSel.value, toSel.value, pre);
      } else {
        pre.textContent = t("versions.single");
        showBtn.disabled = true;
      }
    }).catch(function (err) { showToast(errorText(err), "error"); });
  }

  /* --------------------------------------------------------------- toasts */
  function showToast(message, kind) {
    var el = document.createElement("div");
    el.className = "toast " + (kind || "");
    el.textContent = message;
    $("#toast-root").appendChild(el);
    window.setTimeout(function () { if (el.parentNode) { el.parentNode.removeChild(el); } }, 4000);
  }

  function pushBusy() { state.busy += 1; $("#busy-overlay").hidden = false; }
  function popBusy() {
    state.busy = Math.max(0, state.busy - 1);
    if (state.busy === 0) { $("#busy-overlay").hidden = true; }
  }

  /* ---------------------------------------------------------------- font */
  function loadFont() {
    request("GET", "/api/fonts/Vazirmatn-Regular.ttf", { raw: true }).then(function (r) {
      if (!r.ok) { return; }
      return r.response.arrayBuffer().then(function (buffer) {
        var url = URL.createObjectURL(new Blob([buffer], { type: "font/ttf" }));
        var style = document.createElement("style");
        style.textContent = "@font-face{font-family:'Vazirmatn';src:url('" + url + "') format('truetype');font-display:swap;}";
        document.head.appendChild(style);
      });
    }).catch(function () { /* fall back to the system font */ });
  }

  /* -------------------------------------------------------------- wiring */
  function openMobile(panelId) {
    var panel = $(panelId);
    if (!panel) { return; }
    panel.classList.add("open");
    var backdrop = $("#mobile-backdrop");
    if (backdrop) { backdrop.hidden = false; }
  }

  function closeMobilePanels() {
    $$(".panel").forEach(function (el) { el.classList.remove("open"); });
    var backdrop = $("#mobile-backdrop");
    if (backdrop) { backdrop.hidden = true; }
  }

  function bind() {
    buildFormatToolbar();
    $("#login-form").addEventListener("submit", handleLogin);
    var tokenToggle = $("#token-toggle");
    if (tokenToggle) {
      tokenToggle.addEventListener("click", function () {
        var block = $("#token-block");
        if (block) { block.hidden = false; }
        var hint = $("#claim-hint");
        if (hint) { hint.hidden = true; }
        try { $("#token-input").focus(); } catch (e) { /* ignore */ }
      });
    }
    $("#btn-lock").addEventListener("click", function () {
      request("POST", "/api/session/lock", {}).then(function () { handleLockEvent(); });
    });
    $("#btn-theme").addEventListener("click", toggleTheme);
    $("#global-search-form").addEventListener("submit", function (ev) {
      ev.preventDefault();
      runSearch();
    });
    $("#btn-refresh").addEventListener("click", function () { loadIndex(); loadFolder(state.cwd); });
    $("#btn-menu").addEventListener("click", function () {
      var panel = $("#panel-left");
      if (panel && panel.classList.contains("open")) { closeMobilePanels(); } else { openMobile("#panel-left"); }
    });
    var backdrop = $("#mobile-backdrop");
    if (backdrop) { backdrop.addEventListener("click", closeMobilePanels); }
    $("#global-search-form").addEventListener("submit", function (ev) { ev.preventDefault(); runSearch(); });
    var searchKind = $("#search-kind");
    if (searchKind) {
      searchKind.value = state.searchKind;
      searchKind.addEventListener("change", function () { state.searchKind = searchKind.value; });
    }
    $("#filter-input").addEventListener("input", function () {
      if (state.session && state.session.locked) { return; }
      call("vault.list_folder", { path: state.cwd }).then(function (result) {
        renderFileList(result.entries);
      });
    });
    // Arrow keys walk the centre note list (the sidebar list was removed).
    document.addEventListener("keydown", function (ev) {
      var tag = (document.activeElement && document.activeElement.tagName) || "";
      if (tag === "INPUT" || tag === "TEXTAREA") { return; }
      var items = $$("#notes-list li");
      if (!items.length) { return; }
      if (ev.key === "ArrowDown") { selectIndex(Math.min(items.length - 1, state.selectedIndex + 1)); ev.preventDefault(); }
      else if (ev.key === "ArrowUp") { selectIndex(Math.max(0, state.selectedIndex - 1)); ev.preventDefault(); }
      else if (ev.key === "Enter" && state.selectedIndex >= 0) {
        var entry = state.files && state.files[state.selectedIndex];
        if (entry) { navigateNote(entry.path); }
      }
    });
    ["#btn-new-note", "#btn-new-note-side"].forEach(function (selector) {
      var button = $(selector);
      if (button) { button.addEventListener("click", function () { askNewNote(); }); }
    });
    var newFolderButton = $("#btn-new-folder");
    if (newFolderButton) { newFolderButton.addEventListener("click", function () { askNewFolder(); }); }
    var imageInput = $("#image-input");
    if (imageInput) {
      imageInput.addEventListener("change", function () {
        insertImageFiles(imageInput.files);
        imageInput.value = "";
      });
    }
    // Pasting a screenshot straight into the note is the whole point of this editor.
    $("#editor").addEventListener("paste", function (ev) {
      var items = (ev.clipboardData && ev.clipboardData.files) || [];
      var files = Array.prototype.slice.call(items);
      if (!files.length && ev.clipboardData && ev.clipboardData.items) {
        Array.prototype.slice.call(ev.clipboardData.items).forEach(function (item) {
          if (item.kind === "file") { files.push(item.getAsFile()); }
        });
      }
      if (files.some(function (f) { return f && /^image\//.test(f.type || ""); })) {
        ev.preventDefault();
        insertImageFiles(files);
      }
    });
    $("#editor").addEventListener("input", function () {
      state.dirty = true;
      $("#dirty-indicator").hidden = false;
      updatePreview();
    });
    $("#btn-save").addEventListener("click", saveFile);
    $("#btn-cancel").addEventListener("click", cancelEdit);
    $("#btn-note-edit-top").addEventListener("click", enterEditMode);
    var deleteTop = $("#btn-note-delete-top");
    if (deleteTop) {
      deleteTop.addEventListener("click", function () {
        if (!state.file) { return; }
        deleteEntry({ path: state.file.path, name: state.file.name, is_dir: false });
      });
    }
    var rawHandler = function () {
      if (!state.file || state.file.binary) { return; }
      var path = state.file.path;
      request("GET", "/api/raw?path=" + encodeURIComponent(path), { raw: true }).then(function (r) {
        if (!r.ok) { showToast(t("error.ERROR"), "error"); return; }
        return r.response.text().then(function (text) {
          var blob = new Blob([text], { type: "text/plain;charset=utf-8" });
          var url = URL.createObjectURL(blob);
          var win = window.open(url, "_blank");
          if (!win) { showPlainModal(path, text); }
          window.setTimeout(function () { URL.revokeObjectURL(url); }, 60000);
        });
      });
    };
    $("#btn-note-raw-top").addEventListener("click", rawHandler);
    var historyTop = $("#btn-note-history-top");
    if (historyTop) {
      historyTop.addEventListener("click", function () {
        if (state.file) { openVersions(state.file.path); }
      });
    }
    $("#btn-preview").addEventListener("click", function () {
      if (!state.file || state.file.sensitivity !== "normal") { return; }
      state.preview = !state.preview;
      updatePreview();
    });
    $("#level-select").addEventListener("change", function (ev) { changeLevel(ev.target.value); });
    var noteInput = $("#folder-note-input");
    if (noteInput) {
      noteInput.addEventListener("change", function () {
        call("vault.set_folder_note", { path: state.cwd, text: noteInput.value })
          .then(function () { showToast(t("web.saved"), "ok"); })
          .catch(function (err) { showToast(errorText(err), "error"); });
      });
    }
    var fileNoteInput = $("#file-note-input");
    if (fileNoteInput) {
      fileNoteInput.addEventListener("change", function () {
        if (!state.file) { return; }
        call("vault.set_file_note", { path: state.file.path, text: fileNoteInput.value })
          .then(function () {
            state.file.note = fileNoteInput.value;
            showToast(t("web.saved"), "ok");
          })
          .catch(function (err) { showToast(errorText(err), "error"); });
      });
    }
    $$(".lang-select").forEach(function (select) {
      select.addEventListener("change", function () { setLanguage(select.value); });
    });
    document.addEventListener("click", function (ev) { if (!ev.target.closest(".context-menu")) { closeContextMenu(); } });
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape") { closeContextMenu(); closeAllModals(); closeMobilePanels(); }
      if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "s") { ev.preventDefault(); if (state.editing) { saveFile(); } }
      if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "l") { ev.preventDefault(); $("#btn-lock").click(); }
      if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "f") { ev.preventDefault(); $("#global-search").focus(); }
      if (ev.key === "/" && document.activeElement.tagName !== "INPUT" && document.activeElement.tagName !== "TEXTAREA") {
        ev.preventDefault(); $("#global-search").focus();
      }
    });
    ["click", "keydown", "mousemove"].forEach(function (name) {
      document.addEventListener(name, function () { state.lastActivity = Date.now(); }, { passive: true });
    });
    window.addEventListener("hashchange", function () { if (state.token) { applyRoute(); } });
    window.addEventListener("beforeunload", function (ev) {
      if (state.dirty) { ev.preventDefault(); ev.returnValue = ""; }
    });
  }

  function readTokenFromHash() {
    var hash = window.location.hash || "";
    var match = /#(?:token=)?([0-9a-fA-F]{32,128})$/.exec(hash);
    if (match) {
      state.token = match[1];
      try { sessionStorage.setItem(TOKEN_KEY, state.token); } catch (e) { /* ignore */ }
      try { history.replaceState(null, "", window.location.pathname + window.location.search); } catch (e) { /* ignore */ }
    }
  }

  function init() {
    try { state.lang = sessionStorage.getItem(LANG_KEY) || "fa"; } catch (e) { state.lang = "fa"; }
    try { state.theme = sessionStorage.getItem(THEME_KEY) || "dark"; } catch (e) { state.theme = "dark"; }
    applyDirection();
    applyTheme();
    readTokenFromHash();
    try { state.token = state.token || sessionStorage.getItem(TOKEN_KEY) || ""; } catch (e) { /* ignore */ }
    bind();
    state.searchKind = state.searchKind || "filenames";
    // /api/i18n is public, so the catalogue is loaded even before a token exists — otherwise
    // the unlock screen rendered with every label empty (no text on the fields or the button).
    var ready = loadCatalogue()
      .then(applyI18n)
      .catch(function () { applyI18n(); });
    ready.then(function () {
      if (state.token) {
        setTokenVisibility(true);
        return afterToken();
      }
      // No token yet: ask the local desktop app for one before showing the manual form.
      return claimToken().then(function (claimed) {
        if (!claimed) { setTokenVisibility(false); showLogin(""); return; }
        setTokenVisibility(true);
        return afterToken();
      });
    });
  }

  function afterToken() {
    return request("GET", "/api/session").then(function (r) {
      if (r.status !== 200) { showLogin(t("web.bad_token")); return; }
      var session = r.data || {};
      if (session.locked === true) {
        // The token is good but the vault itself is locked: ask for the password only.
        showLogin("");
        return;
      }
      return enterApp();
    }).catch(function () { showLogin(t("error.ERROR")); });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
