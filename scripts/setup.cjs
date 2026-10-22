// One-shot local setup: create .venv and install runtime + dev dependencies (incl. the spaCy model).
const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const win = process.platform === "win32";
const venvPy = path.join(root, ".venv", win ? "Scripts/python.exe" : "bin/python");
const run = (cmd, args) => {
  console.log(`> ${cmd} ${args.join(" ")}`);
  const r = spawnSync(cmd, args, { cwd: root, stdio: "inherit" });
  if (r.status !== 0) process.exit(r.status ?? 1);
};

if (!fs.existsSync(venvPy)) {
  const candidates = win ? [["py", ["-3.11"]], ["python", []]] : [["python3.11", []], ["python3", []]];
  const found = candidates.find(([c, a]) => spawnSync(c, [...a, "--version"]).status === 0);
  if (!found) { console.error("Python 3.11+ not found."); process.exit(1); }
  run(found[0], [...found[1], "-m", "venv", ".venv"]);
}
run(venvPy, ["-m", "pip", "install", "--upgrade", "pip"]);
run(venvPy, ["-m", "pip", "install", "-r", "requirements-dev.txt"]);
console.log("\nReady. Start the app with:  npm start   →  http://localhost:8077");
