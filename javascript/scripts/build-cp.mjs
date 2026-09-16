import { copyFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = fileURLToPath(new URL("..", import.meta.url));
const sourceDirectory = join(packageRoot, "src");
const distributionDirectory = join(packageRoot, "dist");

for (const file of ["evmole_node.mjs", "evmole_wasm_import.js"]) {
  await copyFile(join(sourceDirectory, file), join(distributionDirectory, file));
}

await rm(join(distributionDirectory, ".gitignore"), { force: true });
