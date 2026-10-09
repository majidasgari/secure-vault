/* Dev-only probe entry (never bundled into the vendored build).
 *
 * Mounts a *plain* Crepe — no vault theme, no labels, no direction plugin, no resolveUrl — so an
 * image or table problem can be attributed to Crepe itself rather than to this wrapper. Served by
 * the Vite dev server (`bunx vite --port 5310` in this directory) and used by
 * `tools/ui_probe_visual_dev.js`.
 */
import { Crepe } from "@milkdown/crepe";
import "@milkdown/crepe/theme/common/style.css";
import "@milkdown/crepe/theme/frame.css";

export async function mountPlain(root, markdown) {
  const crepe = new Crepe({ root, defaultValue: markdown });
  await crepe.create();
  return crepe;
}
