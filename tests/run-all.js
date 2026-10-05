// Usage: node run-all.js [path/to/plugin.js]   (default: ./plugin.js)
// Needs Node 18+. The HTTPS test needs `openssl` on PATH (skipped otherwise).
const { spawnSync, execSync } = require("child_process")
const path = require("path"), fs = require("fs")
const plugin = path.resolve(process.argv[2] || "plugin.js")
if (!fs.existsSync(plugin)) { console.error("plugin not found:", plugin); process.exit(1) }
const env = { ...process.env, PLUGIN: plugin }
const run = (file, expect, extraEnv = {}) => {
  console.log(`\n=== ${file} ===`)
  const r = spawnSync(process.execPath, [path.join(__dirname, file)], { env: { ...env, ...extraEnv }, encoding: "utf8", timeout: 60_000 })
  const out = r.stdout || ""
  process.stdout.write(out); process.stderr.write(r.stderr || "")
  const pass = r.status === 0 && !/FAIL/.test(out) && expect.every(e => out.includes(e))
  if (!pass) console.log("^^^ FAILED" + (expect.length ? " (expected output: " + expect.join(" | ") + ")" : ""))
  return pass
}
let ok = true
ok = run("test-core.js", ["0 failures"]) && ok
ok = run("test-cidr-idle.js", ["0 failures"]) && ok
ok = run("test-dns.js", ["0 failures"]) && ok
ok = run("test-upgrade-fallback.js", ["Upgrade requests with a body are not supported", "end=true /g"]) && ok
ok = run("test-expect-continue.js", ["T body=hi"]) && ok
try {
  const k = path.join(__dirname, "k.pem"), c = path.join(__dirname, "c.pem")
  if (!fs.existsSync(c)) execSync(`openssl req -x509 -newkey rsa:2048 -nodes -keyout "${k}" -out "${c}" -days 3650 -subj /CN=localhost -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"`, { stdio: "ignore" })
  ok = run("test-https.js", ["/sni 200 TLS", "/ip 200 TLS"], { NODE_EXTRA_CA_CERTS: c }) && ok
} catch { console.log("\n=== test-https.js === skipped (openssl not available)") }
console.log(ok ? "\nALL PASSED" : "\nSOME TESTS FAILED"); process.exit(ok ? 0 : 1)
