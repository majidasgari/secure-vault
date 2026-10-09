/* Secure Vault — vendored Milkdown (Crepe) editor.
 *
 * Built by `tools/build_milkdown.sh` into `src/vault/webui/vendor/milkdown-editor.js` and loaded
 * on demand by the SPA (`import("/static/vendor/milkdown-editor.js")`), so nothing here runs until
 * the user asks for the visual editor.
 *
 * Rules this module obeys, because the SPA cannot relax them:
 *   * no storage, no cookies, no network of its own — the caller supplies the document and gets
 *     the markdown back through `onChange`;
 *   * every user-visible string arrives in `options.labels` (the SPA feeds it from /api/i18n);
 *   * uploads and image URLs go through the caller (`upload`, `resolveUrl`), so a `vault:` path is
 *     the only thing that ever ends up in the markdown;
 *   * per-block direction is decided here (node decorations) and never by the surrounding pane.
 */

import { Crepe, CrepeFeature } from "@milkdown/crepe";
import { Plugin, PluginKey } from "@milkdown/prose/state";
import { Decoration, DecorationSet } from "@milkdown/prose/view";
import { $prose, replaceAll } from "@milkdown/utils";

import commonTheme from "@milkdown/crepe/theme/common/style.css?inline";
import frameTheme from "@milkdown/crepe/theme/frame.css?inline";
import vaultTheme from "./theme.css?inline";

export const BUILD = {
  editor: "milkdown-crepe",
  // `define` in vite.config rewrites these at build time; the guards keep the source importable
  // straight from a dev server (`vite` dev does not apply the library `define` map).
  version: typeof __MILKDOWN_VERSION__ === "string" ? __MILKDOWN_VERSION__ : "dev",
  built: typeof __BUILT_AT__ === "string" ? __BUILT_AT__ : "dev"
};

const THEME_ID = "milkdown-vault-theme";

/** Persian/Arabic letters (Hebrew included, like the SPA's own `hasRtlChars`). */
const RTL_RE = /[\u0590-\u05FF\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]/;

/** Containers that must carry the direction as well: list markers and table column order follow them. */
const CONTAINER_NODES = new Set(["blockquote", "bullet_list", "ordered_list", "table"]);

const autoDirection = $prose(
  () =>
    new Plugin({
      key: new PluginKey("vault-auto-direction"),
      props: {
        // `props.attributes` only reaches the document element (and is called with the state
        // alone there), so the per-node `dir` comes from node decorations: prosemirror merges
        // their attributes into each node's own DOM element.
        decorations: (state) => {
          const decorations = [];
          state.doc.descendants((node, pos) => {
            if (node.type.name === "code_block") {
              // A code block is always left to right, whatever language its comments are written in.
              decorations.push(Decoration.node(pos, pos + node.nodeSize, { dir: "ltr" }));
              return;
            }
            if (!node.isTextblock && !CONTAINER_NODES.has(node.type.name)) { return; }
            decorations.push(
              Decoration.node(pos, pos + node.nodeSize, {
                dir: RTL_RE.test(node.textContent) ? "rtl" : "ltr"
              })
            );
          });
          return DecorationSet.create(state.doc, decorations);
        }
      }
    })
);

function injectTheme() {
  if (document.getElementById(THEME_ID)) { return; }
  const style = document.createElement("style");
  style.id = THEME_ID;
  style.textContent = [commonTheme, frameTheme, vaultTheme].join("\n");
  document.head.appendChild(style);
}

function groupLabels(labels) {
  // `undefined` (not null) keeps the item and falls back to Crepe's own English label; `null`
  // would remove the entry from the menu entirely, which is never what a missing translation means.
  const item = (label) => (label ? { label } : undefined);
  return {
    textGroup: {
      label: labels.groupText,
      text: item(labels.text),
      h1: item(labels.h1),
      h2: item(labels.h2),
      h3: item(labels.h3),
      h4: item(labels.h4),
      h5: item(labels.h5),
      h6: item(labels.h6),
      quote: item(labels.quote),
      divider: item(labels.divider)
    },
    listGroup: {
      label: labels.groupList,
      bulletList: item(labels.bulletList),
      orderedList: item(labels.orderedList),
      taskList: item(labels.taskList)
    },
    advancedGroup: {
      label: labels.groupAdvanced,
      image: item(labels.image),
      codeBlock: item(labels.codeBlock),
      table: item(labels.table),
      math: item(labels.math)
    }
  };
}

/**
 * Mount the visual editor inside `options.root`.
 *
 * @param {object} options
 * @param {Element} options.root          container element (emptied by `destroy()`)
 * @param {string}  [options.value]       initial markdown
 * @param {string}  [options.dir]         "rtl" | "ltr" for the pane itself ("rtl" default)
 * @param {object}  options.labels        user-visible strings (see `groupLabels`)
 * @param {function} [options.onChange]   called with the markdown after every document change
 * @param {function} [options.upload]     (File) => Promise<string> — returns the vault path to store
 * @param {function} [options.resolveUrl] (src) => string|Promise<string> — what the DOM shows for a vault path
 * @returns {Promise<{getMarkdown, setMarkdown, focus, destroy, build}>}
 */
export async function createVisualEditor(options) {
  const opts = options || {};
  const labels = opts.labels || {};
  const root = opts.root;
  if (!root) { throw new Error("createVisualEditor: root is required"); }

  injectTheme();
  root.classList.add("vault-visual-editor");
  root.setAttribute("dir", opts.dir === "ltr" ? "ltr" : "rtl");

  const onUpload = typeof opts.upload === "function" ? opts.upload : () => Promise.resolve("");
  const proxyDomURL = typeof opts.resolveUrl === "function" ? opts.resolveUrl : undefined;

  const crepe = new Crepe({
    root,
    defaultValue: opts.value || "",
    features: {
      [CrepeFeature.AI]: false,
      [CrepeFeature.TopBar]: false,
      // KaTeX ships its own web fonts, which the SPA's static allow-list does not serve, and the
      // vault's own preview does not render math either — so the math feature stays off and `$…$`
      // is written to the note as plain text, exactly as before.
      [CrepeFeature.Latex]: false
    },
    featureConfigs: {
      [CrepeFeature.Placeholder]: { text: labels.placeholder || "" },
      [CrepeFeature.BlockEdit]: groupLabels(labels),
      [CrepeFeature.ImageBlock]: {
        onUpload,
        blockOnUpload: onUpload,
        inlineOnUpload: onUpload,
        proxyDomURL,
        blockUploadButton: labels.upload,
        inlineUploadButton: labels.upload,
        blockConfirmButton: labels.confirm,
        inlineConfirmButton: labels.confirm,
        blockUploadPlaceholderText: labels.url,
        inlineUploadPlaceholderText: labels.url,
        blockCaptionPlaceholderText: labels.caption
      },
      [CrepeFeature.LinkTooltip]: {
        editButton: labels.linkEdit,
        removeButton: labels.linkRemove,
        confirmButton: labels.linkConfirm,
        inputPlaceholder: labels.linkPlaceholder
      },
      [CrepeFeature.CodeMirror]: {
        previewToggleText: (previewOnlyMode) =>
          previewOnlyMode ? labels.editCode || labels.previewToggle || "" : labels.previewToggle || "",
        searchPlaceholder: labels.searchLanguage,
        copyText: labels.copyCode,
        noResultText: labels.noResult
      },
      [CrepeFeature.Latex]: { inlineEditConfirm: labels.latexConfirm },
      [CrepeFeature.Toolbar]: {
        boldLabel: labels.bold,
        italicLabel: labels.italic,
        strikethroughLabel: labels.strikethrough,
        codeLabel: labels.code,
        latexLabel: labels.latex,
        linkLabel: labels.link
      }
    }
  });

  crepe.editor.use(autoDirection);

  // The listener is registered *before* create(): a `crepe.on()` call after create lands on a
  // manager the live listener plugin never reads, and the callback silently never fires.
  if (typeof opts.onChange === "function") {
    crepe.on((listener) => {
      listener.markdownUpdated((_ctx, markdown, previous) => {
        if (markdown === previous) { return; }
        opts.onChange(markdown);
      });
    });
  }

  await crepe.create();

  return {
    build: BUILD,
    getMarkdown: () => crepe.getMarkdown(),
    // `replaceAll` dispatches with `addToHistory: false`, which the markdown listener deliberately
    // ignores — callers that swap the whole document must not expect an `onChange` for it.
    setMarkdown: (markdown) => { crepe.editor.action(replaceAll(markdown, true)); },
    focus: () => { root.querySelector(".ProseMirror")?.focus(); },
    destroy: () => {
      const element = root.querySelector(".milkdown");
      const done = crepe.destroy();
      element?.remove();
      return done;
    }
  };
}
