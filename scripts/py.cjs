// Run the project's venv Python cross-platform: `node scripts/py.cjs -m eval.run_eval`
const { spawnSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const root = path.resolve(__dirname, "..");
const candidates = [
  path.join(root, ".venv", "Scripts", "python.exe"),
  path.join(root, ".venv", "bin", "python"),
];
const py = candidates.find((p) => fs.existsSync(p));
if (!py) {
  console.error("No .venv found. Create one first:\n  python -m venv .venv && .venv/bin/pip install -r requirements.txt");
  process.exit(1);
}
const res = spawnSync(py, process.argv.slice(2), { cwd: root, stdio: "inherit" });
process.exit(res.status ?? 1);
