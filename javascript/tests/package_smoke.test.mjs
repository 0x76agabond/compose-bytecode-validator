import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const packageRoot = fileURLToPath(new URL("..", import.meta.url));
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const npmOptions = process.platform === "win32" ? { shell: true } : {};

test("npm package exports direct storage validation", { timeout: 120_000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "evmole-package-"));
  const environment = {
    ...process.env,
    npm_config_cache: join(directory, "npm-cache"),
  };
  delete environment.NODE_TEST_CONTEXT;
  const packed = spawnSync(npmCommand, ["pack", "--json"], {
    cwd: packageRoot,
    encoding: "utf8",
    env: environment,
    ...npmOptions,
  });
  assert.equal(packed.status, 0, packed.stderr);
  const packJson = JSON.parse(packed.stdout);
  const { filename, files } = Array.isArray(packJson)
    ? packJson[0]
    : Object.values(packJson)[0];
  const paths = new Set(files.map((file) => file.path));
  for (const required of [
    "dist/evmole_bg.wasm",
    "dist/evmole_node.mjs",
    "dist/evmole.d.ts",
  ]) {
    assert.ok(paths.has(required), `missing ${required}`);
  }
  assert.ok(![...paths].some((path) => path.startsWith("tests/")));

  const tarball = join(packageRoot, basename(filename));
  const install = spawnSync(
    npmCommand,
    ["install", "--ignore-scripts", "--no-audit", "--no-fund", tarball],
    { cwd: directory, encoding: "utf8", env: environment, ...npmOptions },
  );
  assert.equal(install.status, 0, install.stderr);
  const library = await import(pathToFileURL(join(
    directory,
    "node_modules",
    "compose-bytecode-validator",
    "dist",
    "evmole_node.mjs",
  )).href);
  const report = library.validateStorage({
    bytecode: "0x6001600055",
    virtualStorageLayout: { records: [] },
  });
  assert.deepEqual(report.collisions, []);
  assert.ok(Array.isArray(report.uncertainScopes));

  const packageJson = JSON.parse(
    await readFile(
      join(directory, "node_modules", "compose-bytecode-validator", "package.json"),
      "utf8",
    ),
  );
  assert.equal(packageJson.name, "compose-bytecode-validator");
});
