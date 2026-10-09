/* Build-time stub for @codemirror/language-data.
 *
 * Crepe's code-block feature pulls that package, which drags every grammar CodeMirror ships
 * (≈120 dynamic chunks, ~1.5 MB) into the vendored bundle. The vault only needs the handful of
 * languages its notes actually use, so the build aliases the package to this list. Everything not
 * listed still renders as a plain code block — just without highlighting.
 */

import { json } from "@codemirror/lang-json";
import { javascript } from "@codemirror/lang-javascript";
import { python } from "@codemirror/lang-python";

export const languages = [
  { name: "JavaScript", alias: ["js", "jsx", "node"], load: () => Promise.resolve(javascript()) },
  { name: "TypeScript", alias: ["ts", "tsx"], load: () => Promise.resolve(javascript({ typescript: true })) },
  { name: "Python", alias: ["py"], load: () => Promise.resolve(python()) },
  { name: "JSON", alias: ["json"], load: () => Promise.resolve(json()) }
];
