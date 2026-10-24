// Copies the pinned htmx build into the Python package's static directory.
// npm ci has already checked every file against the integrity hashes in package-lock.json.
import { copyFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const source = join(root, "node_modules", "htmx.org");
const target = join(root, "src", "drydock", "static", "vendor", "htmx");
const expectedVersion = "4.0.0";

const manifest = JSON.parse(readFileSync(join(source, "package.json"), "utf8")) as {
  version: string;
};
if (manifest.version !== expectedVersion) {
  throw new Error(`htmx.org ${manifest.version} is installed; drydock pins ${expectedVersion}.`);
}

const files = ["htmx.min.js", "ext/hx-csp.min.js"];
for (const file of files) {
  const destination = join(target, file);
  mkdirSync(dirname(destination), { recursive: true });
  copyFileSync(join(source, "dist", file), destination);
}
console.log(`vendored htmx ${manifest.version}: ${files.join(", ")}`);
