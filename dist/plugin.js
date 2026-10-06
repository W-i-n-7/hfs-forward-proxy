/*
 * HFS HTTPS Forward Proxy
 *
 * Install as: .hfs/plugins/https-forward-proxy/plugin.js
 * The proxy uses HFS's existing HTTP/HTTPS listener, so do not configure a
 * second listen port or certificate. HTTPS proxy clients connect to the HFS
 * HTTPS URL and use Proxy-Authorization.
 */
"use strict"

const http = require("http")
const https = require("https")
const net = require("net")
const dns = require("dns").promises
const crypto = require("crypto")

exports.repo = "W-i-n-7/hfs-forward-proxy"
exports.description = "Authenticated HTTP, HTTPS CONNECT, and WebSocket forward proxy for HFS (This plugin is AI generated!)"
exports.version = 1.01
exports.apiRequired = 13.4
exports.changelog = [
    { "version": 1.01, "message": "Options UI fix" }
]

exports.config = {
  users: {
    type: "array",
    label: "Proxy users",
    fields: {
      username: { label: "Username", required: true, $width: 1 },
      password: { label: "Password", required: true, inputProps: { type: "password" }, $hideUnder: true },
    },
  },
  allowLanIpAccess: {
    type: "boolean",
    label: "Allow private/LAN destinations",
    defaultValue: false,
    helperText: "When enabled, LAN IP list controls which private addresses are allowed.",
  },
  lanIpList: {
    type: "array",
    label: "LAN IP list",
    fields: { ip: { label: "IP address or CIDR range", required: true, helperText: "e.g. 192.168.1.20, 192.168.1.0/24, fd00::/8" } },
  },
  lanIpListIsWhitelist: {
    type: "boolean",
    label: "Treat LAN IP list as a whitelist",
    defaultValue: false,
  },
  allowOtherPorts: {
    type: "boolean",
    label: "Allow destination ports other than 80 and 443",
    defaultValue: false,
    helperText: "Ports 80 and 443 are always allowed. When enabled, the port list below controls which other ports are allowed.",
  },
  portListIsWhitelist: {
    type: "boolean",
    label: "Treat port list as a whitelist",
    defaultValue: true,
    helperText: "On: only listed ports are allowed. Off: every port is allowed except listed ones.",
    showIf: values => values.allowOtherPorts,
  },
  additionalAllowedPorts: {
    type: "array",
    label: "Port list",
    showIf: values => values.allowOtherPorts,
    fields: { port: { type: "number", label: "Port", min: 1, max: 65535, required: true } },
  },
  idleTimeoutSeconds: {
    type: "number",
    label: "Idle timeout for open connections (seconds)",
    defaultValue: 300,
    min: 0,
    max: 86400,
    helperText: "Closes downloads and tunnels with no traffic in either direction for this long. 0 = never.",
  },
  fail2banEnabled: { type: "boolean", label: "Enable failed-authentication bans", defaultValue: true },
  fail2banMaxAttempts: { type: "number", label: "Failed attempts before ban", defaultValue: 5, min: 1, max: 100 },
  fail2banWindowMinutes: { type: "number", label: "Attempt window (minutes)", defaultValue: 10, min: 1, max: 1440 },
  fail2banBanMinutes: { type: "number", label: "Ban duration (minutes)", defaultValue: 60, min: 1, max: 10080 },
}

exports.init = async api => {
  const failedAuthentication = new Map()
  const patchedServers = new Map() // server -> restore function

  // HFS may or may not merge defaultValue into getConfig(); apply them here so
  // behaviour always matches what the settings page shows.
  const defaults = Object.fromEntries(Object.entries(exports.config).filter(([, v]) => "defaultValue" in v).map(([k, v]) => [k, v.defaultValue]))
  const cfg = () => ({ ...defaults, ...(api.getConfig() || {}) })
  const users = () => Object.fromEntries((cfg().users || []).filter(x => x?.username).map(x => [String(x.username), String(x.password ?? "")]))
  const validPort = port => Number.isInteger(port) && port >= 1 && port <= 65535
  const portAllowed = port => {
    if (!validPort(port)) return false
    if (port === 80 || port === 443) return true
    const c = cfg()
    if (!c.allowOtherPorts) return false
    const list = (c.additionalAllowedPorts || []).map(x => Number(x?.port ?? x)).filter(validPort)
    return c.portListIsWhitelist !== false ? list.includes(port) : !list.includes(port)
  }
  const log = (...args) => api.log("[https-forward-proxy]", ...args)
  const ipOf = socket => socket?.remoteAddress || "unknown"
  const redact = url => String(url || "").replace(/\/\/[^/@]*@/, "//***@")

  class PolicyError extends Error {}

  function constantTimeEqual(a, b) {
    // Hash first so comparison time doesn't leak the password length.
    const left = crypto.createHash("sha256").update(String(a)).digest()
    const right = crypto.createHash("sha256").update(String(b)).digest()
    return crypto.timingSafeEqual(left, right)
  }

  function authenticate(req) {
    const header = req.headers["proxy-authorization"]
    if (typeof header !== "string" || !/^Basic /i.test(header)) return null
    const decoded = Buffer.from(header.slice(6).trim(), "base64").toString("utf8")
    const i = decoded.indexOf(":")
    if (i < 1) return null
    const username = decoded.slice(0, i)
    const password = decoded.slice(i + 1)
    const configured = users()
    const known = Object.prototype.hasOwnProperty.call(configured, username)
    // Always run the comparison so response time doesn't reveal whether the username exists.
    const match = constantTimeEqual(password, known ? configured[username] : "\0invalid")
    return known && match ? username : null
  }

  function isBanned(ip) {
    if (!cfg().fail2banEnabled) return false
    const item = failedAuthentication.get(ip)
    if (!item?.bannedUntil) return false
    if (item.bannedUntil > Date.now()) return true
    failedAuthentication.delete(ip)
    return false
  }

  function failedAuth(ip) {
    const c = cfg()
    if (!c.fail2banEnabled) return false
    const now = Date.now()
    const windowMs = Number(c.fail2banWindowMinutes || 10) * 60_000
    const item = failedAuthentication.get(ip) || { attempts: [], bannedUntil: 0 }
    item.attempts = item.attempts.filter(t => t > now - windowMs)
    item.attempts.push(now)
    failedAuthentication.set(ip, item)
    if (item.attempts.length < Number(c.fail2banMaxAttempts || 5)) return false
    item.bannedUntil = now + Number(c.fail2banBanMinutes || 60) * 60_000
    log("banned", ip)
    return true
  }

  function clearAuth(ip) { failedAuthentication.delete(ip) }

  // Hop-by-hop headers must not be forwarded (RFC 9110 §7.6.1).
  const HOP_BY_HOP = ["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade"]
  function stripHopByHop(headers, keepUpgrade = false) {
    const result = { ...headers }
    const listed = String(headers.connection || "").toLowerCase().split(",").map(x => x.trim()).filter(Boolean)
    for (const h of [...HOP_BY_HOP, ...listed]) if (!(keepUpgrade && (h === "upgrade" || h === "connection"))) delete result[h]
    delete result["proxy-authorization"]; delete result["proxy-connection"]
    return result
  }

  function errorResponse(res, status, message, extraHeaders = {}) {
    if (!res || res.writableEnded || res.destroyed) return
    if (res.headersSent) { res.destroy(); return } // can't send an error mid-body; abort so the client notices
    const body = `${message}\n`
    res.writeHead(status, { "Content-Type": "text/plain", Connection: "close", "Content-Length": Buffer.byteLength(body), ...extraHeaders })
    res.end(body)
  }
  const STATUS_TEXT = { 400: "Bad Request", 403: "Forbidden", 407: "Proxy Authentication Required", 502: "Bad Gateway", 504: "Gateway Timeout" }
  function errorSocket(socket, status, message) {
    if (!socket || socket.destroyed) return
    const body = `${message}\n`
    const auth = status === 407 ? 'Proxy-Authenticate: Basic realm="HFS HTTPS proxy"\r\n' : ""
    socket.end(`HTTP/1.1 ${status} ${STATUS_TEXT[status] || ""}\r\n${auth}Connection: close\r\nContent-Type: text/plain\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`)
  }

  const privateRanges = new net.BlockList()
  for (const [a, p] of [["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 3]]) privateRanges.addSubnet(a, p, "ipv4")
  for (const [a, p] of [["::", 96], ["::ffff:0:0:0", 96], ["64:ff9b:1::", 48], ["100::", 64], ["2001:db8::", 32], ["fc00::", 7], ["fe80::", 10], ["fec0::", 10], ["ff00::", 8]]) privateRanges.addSubnet(a, p, "ipv6")
  // Canonical form so "0:0::1", "::1" and "::ffff:7f00:1" compare consistently.
  const hexToV4 = (a, b) => { const hi = parseInt(a, 16), lo = parseInt(b, 16); return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}` }
  function canonicalIp(ip) {
    if (net.isIPv4(ip) || !net.isIPv6(ip)) return ip
    try {
      const c = new URL("http://[" + ip + "]/").hostname.slice(1, -1)
      const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(c)
      return mapped ? hexToV4(mapped[1], mapped[2]) : c
    } catch { return ip } // e.g. zone IDs ("fe80::1%eth0"); privateIp() treats these as private
  }
  // IPv4 embedded in NAT64 (64:ff9b::/96) or 6to4 (2002::/16) addresses.
  function embeddedV4(ip) {
    const nat64 = /^64:ff9b::([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(ip)
    if (nat64) return hexToV4(nat64[1], nat64[2])
    const sixToFour = /^2002:([0-9a-f]{1,4}):([0-9a-f]{1,4})(:|$)/.exec(ip)
    return sixToFour ? hexToV4(sixToFour[1], sixToFour[2]) : null
  }
  function privateIp(ip) {
    try {
      const c = canonicalIp(ip)
      if (net.isIPv4(c)) return privateRanges.check(c, "ipv4")
      if (!net.isIPv6(c) || c.includes("%")) return true
      const v4 = embeddedV4(c)
      return privateRanges.check(c, "ipv6") || (v4 !== null && privateRanges.check(v4, "ipv4"))
    } catch { return true } // fail closed
  }
  // LAN IP list entries: single addresses or CIDR ranges. Rebuilt only when the setting changes.
  let lanCache = { key: null, list: null }
  function lanList(entries) {
    const key = JSON.stringify(entries || [])
    if (lanCache.key === key) return lanCache.list
    const list = new net.BlockList()
    for (const entry of entries || []) {
      const text = String(entry?.ip ?? entry).trim()
      const [addr, prefix, extra] = text.split("/")
      const ip = canonicalIp(addr.trim())
      const family = net.isIPv4(ip) ? "ipv4" : net.isIPv6(ip) ? "ipv6" : null
      const bits = prefix === undefined ? null : Number(prefix)
      const max = net.isIPv6(addr.trim()) ? 128 : 32 // prefix length is relative to the address as written
      if (!family || extra !== undefined || (bits !== null && !(Number.isInteger(bits) && bits >= 0 && bits <= max && /^\d+$/.test(prefix.trim())))) { log("ignoring invalid LAN IP list entry:", text); continue }
      // An IPv4-mapped entry like ::ffff:10.0.0.0/104 is canonicalised to IPv4, so shift its prefix.
      const v4FromV6 = family === "ipv4" && net.isIPv6(addr.trim())
      if (bits === null) list.addAddress(ip, family)
      else if (v4FromV6) { if (bits >= 96) list.addSubnet(ip, bits - 96, "ipv4"); else { log("ignoring invalid LAN IP list entry:", text); continue } }
      else list.addSubnet(ip, bits, family)
    }
    lanCache = { key, list }
    return list
  }
  const inList = (list, ip) => { try { return list.check(ip, net.isIPv4(ip) ? "ipv4" : "ipv6") } catch { return false } }
  // ---- DNS --------------------------------------------------------------
  // dns.lookup() runs on libuv's small thread pool (4 threads by default), which HFS also uses for
  // file I/O, so slow DNS could stall file serving. Public names are resolved with c-ares
  // (dns.Resolver), which doesn't use the pool. dns.lookup() is only used for local names (hosts
  // file, "localhost", LAN/NetBIOS/mDNS names) or when c-ares finds nothing, and is limited to
  // LOOKUP_CONCURRENCY at a time so the pool always has threads left for HFS.
  const DNS_TIMEOUT_MS = 8000
  const LOOKUP_CONCURRENCY = 2
  const CACHE_MIN_S = 5, CACHE_MAX_S = 60, CACHE_MAX_ENTRIES = 1000
  const resolver = new dns.Resolver({ timeout: 2500, tries: 2 })
  const dnsCache = new Map() // hostname -> { addresses, expires }
  let lookupsActive = 0
  const lookupQueue = []

  function withTimeout(promise, ms, message) {
    let timer
    return Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(Error(message)), ms) })]).finally(() => clearTimeout(timer))
  }
  async function limitedLookup(hostname) {
    if (lookupsActive >= LOOKUP_CONCURRENCY) await new Promise(r => lookupQueue.push(r)) // slot is handed over by the finisher
    else lookupsActive++
    try { return await dns.lookup(hostname, { all: true, verbatim: true }) }
    finally { const next = lookupQueue.shift(); if (next) next(); else lookupsActive-- }
  }
  const localName = h => !h.includes(".") || /\.(local|localhost|lan|home|internal|intranet|home\.arpa)$/i.test(h)
  function cachePut(key, addresses, ttlSeconds) {
    if (dnsCache.size >= CACHE_MAX_ENTRIES) dnsCache.delete(dnsCache.keys().next().value)
    const ttl = Math.min(CACHE_MAX_S, Math.max(CACHE_MIN_S, Number(ttlSeconds) || CACHE_MAX_S))
    dnsCache.set(key, { addresses, expires: Date.now() + ttl * 1000 })
  }
  async function resolveUncached(hostname) {
    if (!localName(hostname)) {
      const [v4, v6] = await Promise.allSettled([resolver.resolve4(hostname, { ttl: true }), resolver.resolve6(hostname, { ttl: true })])
      const records = [
        ...(v4.status === "fulfilled" ? v4.value.map(r => ({ address: r.address, family: 4, ttl: r.ttl })) : []),
        ...(v6.status === "fulfilled" ? v6.value.map(r => ({ address: r.address, family: 6, ttl: r.ttl })) : []),
      ]
      if (records.length) return { addresses: records.map(({ address, family }) => ({ address, family })), ttl: Math.min(...records.map(r => r.ttl)) }
      // Nothing from c-ares (hosts-file-only name, split DNS, no DNS servers configured...): ask the OS.
    }
    return { addresses: await limitedLookup(hostname), ttl: 30 }
  }
  async function resolveName(hostname) {
    if (net.isIP(hostname)) { const literal = { address: hostname, family: net.isIP(hostname) }; return [literal] }
    const key = hostname.toLowerCase()
    const hit = dnsCache.get(key)
    if (hit && hit.expires > Date.now()) return hit.addresses
    if (hit) dnsCache.delete(key)
    const { addresses, ttl } = await withTimeout(resolveUncached(key), DNS_TIMEOUT_MS, "DNS lookup timed out")
    if (addresses.length) cachePut(key, addresses, ttl)
    return addresses
  }

  async function resolve(hostname) {
    hostname = String(hostname || "").replace(/^\[|\]$/g, "") // URL keeps brackets on IPv6 literals
    if (!hostname) throw new PolicyError("Missing destination host")
    const addresses = (await resolveName(hostname)).map(x => ({ ...x, address: canonicalIp(x.address) }))
    if (!addresses.length) throw Error("Destination did not resolve")
    const publicAddress = addresses.find(x => !privateIp(x.address))
    if (publicAddress) return publicAddress
    const c = cfg()
    if (!c.allowLanIpAccess) throw new PolicyError("LAN/private destination blocked")
    const list = lanList(c.lanIpList)
    const permitted = addresses.find(x => c.lanIpListIsWhitelist ? inList(list, x.address) : !inList(list, x.address))
    if (!permitted) throw new PolicyError(c.lanIpListIsWhitelist ? "LAN/private destination not in whitelist" : "LAN/private destination is blacklisted")
    return permitted
  }
  // Path + query exactly as sent (new URL() would normalise "/a/../b", re-encode characters, etc.).
  const rawPath = url => { const p = String(url).replace(/^[a-z][a-z0-9+.-]*:\/\/[^\/?#]*/i, "").replace(/#.*$/, ""); return p.startsWith("/") ? p : `/${p}` }
  const resolveStatus = e => e instanceof PolicyError ? 403 : 502
  function connectTarget(value) {
    const m = /^(\[[0-9a-fA-F:.]+\]|[^:\[\]\s\/]+):(\d{1,5})$/.exec(value || "")
    if (!m) return null
    const port = Number(m[2])
    return validPort(port) ? { hostname: m[1].replace(/^\[|\]$/g, ""), port } : null
  }
  // Returns null when allowed, otherwise [status, message].
  function checkAuth(req, kind) {
    const ip = ipOf(req.socket)
    if (isBanned(ip)) { log("blocked", kind, ip, "banned"); return [403, "Client temporarily banned"] }
    if (!authenticate(req)) {
      // Clients (browsers especially) first try without credentials and only send them after a 407,
      // so only count attempts that actually supplied wrong credentials.
      const banned = req.headers["proxy-authorization"] ? failedAuth(ip) : false
      log("blocked", kind, ip, banned ? "authentication failed; client banned" : "authentication failed")
      return banned ? [403, "Client temporarily banned"] : [407, "Proxy authentication required"]
    }
    clearAuth(ip); return null
  }
  const idleMs = () => Math.max(0, Number(cfg().idleTimeoutSeconds) || 0) * 1000
  // Socket timeouts count activity in both directions on the upstream socket.
  function armIdle(upstream, onIdle) {
    const ms = idleMs()
    upstream.setTimeout(ms) // 0 disables
    if (ms) upstream.once("timeout", onIdle)
  }
  function pipeTunnel(client, upstream) {
    client.on("error", () => upstream.destroy()); client.on("close", () => upstream.destroy())
    upstream.on("close", () => { if (!client.destroyed) client.destroy() })
  }

  async function handleRequest(req, res) {
    const denied = checkAuth(req, "HTTP")
    if (denied) return errorResponse(res, denied[0], denied[1], denied[0] === 407 ? { "Proxy-Authenticate": 'Basic realm="HFS HTTPS proxy"' } : {})
    let target
    try { target = new URL(req.url) } catch { return errorResponse(res, 400, "Expected an absolute HTTP URL") }
    if (!["http:", "https:"].includes(target.protocol)) return errorResponse(res, 400, "Only HTTP and HTTPS URLs are supported")
    const port = Number(target.port || (target.protocol === "https:" ? 443 : 80))
    if (!portAllowed(port)) return errorResponse(res, 403, "Destination port is not allowed")
    let destination
    try { destination = await resolve(target.hostname) } catch (e) { log("blocked", redact(req.url), e.message); return errorResponse(res, resolveStatus(e), e.message) }
    if (res.destroyed || req.destroyed) return // client went away during DNS lookup
    const headers = stripHopByHop(req.headers); headers.host = target.host
    const transport = target.protocol === "https:" ? https : http
    const bareHost = target.hostname.replace(/^\[|\]$/g, "")
    const upstream = transport.request({
      host: destination.address, port, family: destination.family,
      servername: net.isIP(bareHost) ? undefined : bareHost, // SNI must not be an IP
      method: req.method, path: rawPath(req.url), headers,
    }, r => {
      if (res.headersSent || res.writableEnded) return r.resume()
      upstream.removeAllListeners("timeout") // drop the 30 s connect/response timer
      armIdle(upstream, () => { log("HTTP idle timeout", redact(req.url)); upstream.destroy(); res.destroy() })
      res.writeHead(r.statusCode || 502, stripHopByHop(r.headers))
      r.on("error", () => res.destroy()); r.on("aborted", () => res.destroy())
      r.pipe(res)
    })
    upstream.setTimeout(30_000, () => { upstream.destroy(); errorResponse(res, 504, "Upstream timeout") })
    upstream.on("error", e => { log("HTTP upstream error", e.message); errorResponse(res, 502, "Unable to connect to destination") })
    res.on("close", () => { if (!res.writableFinished) upstream.destroy() }) // client aborted
    req.pipe(upstream)
  }

  async function handleConnect(req, client, head) {
    const denied = checkAuth(req, "CONNECT")
    if (denied) return errorSocket(client, ...denied)
    const target = connectTarget(req.url)
    if (!target) return errorSocket(client, 400, "Expected CONNECT host:port")
    if (!portAllowed(target.port)) return errorSocket(client, 403, "Destination port is not allowed")
    let destination
    try { destination = await resolve(target.hostname) } catch (e) { log("blocked", req.url, e.message); return errorSocket(client, resolveStatus(e), e.message) }
    if (client.destroyed) return
    const upstream = net.createConnection({ host: destination.address, port: target.port, family: destination.family })
    let connected = false
    upstream.setTimeout(30_000, () => { if (!connected) errorSocket(client, 504, "Upstream timeout"); upstream.destroy() })
    upstream.once("connect", () => {
      connected = true; client.setTimeout(0)
      upstream.removeAllListeners("timeout") // drop the 30 s connect timer
      armIdle(upstream, () => { upstream.destroy(); client.destroy() })
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n")
      if (head?.length) upstream.write(head)
      client.pipe(upstream); upstream.pipe(client)
    })
    upstream.on("error", e => { log("CONNECT upstream error", e.message); if (!connected) errorSocket(client, 502, "Unable to connect to destination"); else client.destroy() })
    pipeTunnel(client, upstream)
  }

  async function handleUpgrade(req, client, head) {
    const denied = checkAuth(req, "UPGRADE")
    if (denied) return errorSocket(client, ...denied)
    let target
    try { target = new URL(req.url) } catch { return errorSocket(client, 400, "Expected an absolute WebSocket URL") }
    if (!["ws:", "http:"].includes(target.protocol)) return errorSocket(client, 400, "Use CONNECT for wss:// and https:// upgrades")
    const port = Number(target.port || 80)
    if (!portAllowed(port)) return errorSocket(client, 403, "Destination port is not allowed")
    let destination
    try { destination = await resolve(target.hostname) } catch (e) { log("blocked", redact(req.url), e.message); return errorSocket(client, resolveStatus(e), e.message) }
    if (client.destroyed) return
    const upstream = net.createConnection({ host: destination.address, port, family: destination.family })
    let connected = false
    upstream.setTimeout(30_000, () => { if (!connected) errorSocket(client, 504, "Upstream timeout"); upstream.destroy() })
    upstream.once("connect", () => {
      connected = true; client.setTimeout(0)
      upstream.removeAllListeners("timeout") // drop the 30 s connect timer
      armIdle(upstream, () => { upstream.destroy(); client.destroy() })
      const headers = stripHopByHop(req.headers, true); headers.host = target.host
      let text = `${req.method} ${rawPath(req.url)} HTTP/${req.httpVersion}\r\n`
      for (const [k, v] of Object.entries(headers)) for (const one of [].concat(v)) text += `${k}: ${one}\r\n`
      upstream.write(`${text}\r\n`)
      if (head?.length) upstream.write(head)
      client.pipe(upstream); upstream.pipe(client)
    })
    upstream.on("error", e => { log("UPGRADE upstream error", e.message); if (!connected) errorSocket(client, 502, "Unable to connect to destination"); else client.destroy() })
    pipeTunnel(client, upstream)
  }

  const isProxyRequest = req => /^https?:\/\//i.test(req?.url || "")
  const isProxyUpgrade = req => /^(wss?|https?):\/\//i.test(req?.url || "")

  function serveAsRequest(server, emit, req, socket, head) {
    // Node has already handed any request body to us as raw bytes, so HFS couldn't read it; refuse
    // rather than silently dropping it. Body-less requests (the normal case, e.g. curl --http2) work.
    if (head?.length || Number(req.headers["content-length"]) > 0 || req.headers["transfer-encoding"]) return errorSocket(socket, 400, "Upgrade requests with a body are not supported")
    const res = new http.ServerResponse(req)
    res.shouldKeepAlive = false
    res.assignSocket(socket)
    res.on("finish", () => { res.detachSocket(socket); socket.end() })
    socket.on("error", () => socket.destroy())
    emit.call(server, "request", req, res)
  }

  function patchServer(server) {
    if (patchedServers.has(server)) return patchedServers.get(server)
    // Intercept at emit level so HFS never sees proxy traffic. prependListener
    // isn't enough: HFS's own "request" listener would still answer
    // absolute-form requests and clash with the proxied response.
    const originalEmit = server.emit
    // Node only emits "connect"/"upgrade" when a listener exists, so register no-ops.
    const noop = () => {}
    server.on("connect", noop)
    server.on("upgrade", noop)
    const fail = (kind, socket) => e => { log(kind, "error", e?.message); socket?.destroy() }
    server.emit = function (event, ...args) {
      const [req, sock] = args
      if ((event === "checkContinue" || event === "checkExpectation") && isProxyRequest(req)) {
        // Only emitted if HFS registered these listeners; proxy requests must still never reach HFS.
        if (event === "checkContinue") sock.writeContinue()
        else if (!/^100-continue$/i.test(req.headers.expect || "")) { errorResponse(sock, 417, "Expectation failed"); return true }
        event = "request"
      }
      if (event === "request" && isProxyRequest(req)) { handleRequest(...args).catch(e => { log("HTTP error", e?.message); errorResponse(sock, 502, "Proxy error") }); return true }
      if (event === "connect") { handleConnect(...args).catch(fail("CONNECT", sock)); return true }
      if (event === "upgrade") {
        if (isProxyUpgrade(req)) { handleUpgrade(...args).catch(fail("UPGRADE", sock)); return true }
        // Without our no-op, Node would have ignored the Upgrade header and served a normal request.
        if (server.listeners("upgrade").every(l => l === noop)) { serveAsRequest(this, originalEmit, req, sock, args[2]); return true }
      }
      return originalEmit.apply(this, [event, ...args])
    }
    const restore = () => {
      if (!patchedServers.has(server)) return
      patchedServers.delete(server)
      server.removeListener("connect", noop); server.removeListener("upgrade", noop)
      if (server.emit !== originalEmit) server.emit = originalEmit
    }
    patchedServers.set(server, restore)
    return restore
  }

  await api.onServer(patchServer)

  const cleanup = setInterval(() => {
    const now = Date.now()
    const windowMs = Number(cfg().fail2banWindowMinutes || 10) * 60_000
    for (const [ip, item] of failedAuthentication) { item.attempts = item.attempts.filter(t => t > now - windowMs); if (!item.attempts.length && item.bannedUntil <= now) failedAuthentication.delete(ip) }
  }, 60_000)
  cleanup.unref()
  return {
    unload() {
      clearInterval(cleanup)
      failedAuthentication.clear()
    dnsCache.clear()
      for (const restore of [...patchedServers.values()]) restore() // undo the emit patch even if HFS doesn't call onServer's cleanup
    },
  }
}
