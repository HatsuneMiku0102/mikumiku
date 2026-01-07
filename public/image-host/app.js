const API_URL = "/user-image-api"

window.addEventListener("error", (e) => {
  try {
    const msg = String(e?.message || "")
    if (msg.includes("apiKey is not defined")) {
      console.error("apiKey ReferenceError source:", e?.filename, e?.lineno, e?.colno)
      alert(`apiKey ReferenceError in:\n${e?.filename}\nline ${e?.lineno}:${e?.colno}`)
    }
  } catch {}
})


const uploadForm = document.getElementById("uploadForm")
const uploadFile = document.getElementById("uploadFile")
const fileLabel = document.getElementById("fileLabel")

const fetchForm = document.getElementById("fetchForm")
const fetchUrl = document.getElementById("fetchUrl")

const statusEl = document.getElementById("status")
const resultEl = document.getElementById("result")
const errorBox = document.getElementById("errorBox")

const previewImg = document.getElementById("previewImg")
const directUrl = document.getElementById("directUrl")
const pageUrl = document.getElementById("pageUrl")
const directOpen = document.getElementById("directOpen")
const pageOpen = document.getElementById("pageOpen")
const meta = document.getElementById("meta")
const apiLabel = document.getElementById("apiLabel")

const logoutBtn = document.getElementById("logoutBtn")

const keyNameEl = document.getElementById("keyName")
const activeKeyEl = document.getElementById("activeKey")
const generateBtn = document.getElementById("generateKeyBtn")
const keyStatusEl = document.getElementById("keyStatus")
const curlUpload = document.getElementById("curlUpload")
const curlFetch = document.getElementById("curlFetch")

apiLabel.textContent = API_URL

function setStatus(kind, text) {
  statusEl.className = `status ${kind}`
  statusEl.textContent = text
}

function setKeyStatus(kind, text) {
  keyStatusEl.className = `status ${kind}`
  keyStatusEl.textContent = text
}

function showError(err) {
  resultEl.classList.add("hidden")
  errorBox.classList.remove("hidden")
  errorBox.textContent = typeof err === "string" ? err : JSON.stringify(err, null, 2)
  setStatus("err", "Error")
}

function showResult(data) {
  errorBox.classList.add("hidden")
  resultEl.classList.remove("hidden")

  directUrl.value = data.direct_url || ""
  pageUrl.value = data.page_url || ""

  directOpen.href = data.direct_url || "#"
  pageOpen.href = data.page_url || "#"

  previewImg.src = data.direct_url || ""

  const bits = []
  if (data.id) bits.push(`id: ${data.id}`)
  if (data.mime) bits.push(`type: ${data.mime}`)
  if (typeof data.size_bytes === "number") bits.push(`size: ${formatBytes(data.size_bytes)}`)
  meta.textContent = bits.join(" • ")

  setStatus("ok", "Done")
}

function formatBytes(n) {
  if (!Number.isFinite(n)) return ""
  const units = ["B", "KB", "MB", "GB"]
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i += 1
  }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`
}

function buildCurlUpload(imageHost, key) {
  return `curl -i -X POST "${imageHost}/upload" -H "Authorization: Bearer ${key}" -F "file=@C:\\path\\to\\image.png"`
}

function buildCurlFetch(imageHost, key) {
  return `curl -i -X POST "${imageHost}/fetch" -H "Authorization: Bearer ${key}" -H "Content-Type: application/x-www-form-urlencoded" --data "url=https://example.com/image.png"`
}

function setKeyUi(imageHost, key) {
  const host = String(imageHost || "").trim()
  const k = String(key || "").trim()

  activeKeyEl.value = k
  curlUpload.value = host && k ? buildCurlUpload(host, k) : ""
  curlFetch.value = host && k ? buildCurlFetch(host, k) : ""
}

async function loadUserKeys() {
  setKeyStatus("busy", "Loading…")
  setKeyUi("", "")

  const res = await fetch("/api/user/keys", { credentials: "include" })
  const text = await res.text()
  if (!res.ok) throw new Error(text || `HTTP ${res.status}`)

  const data = JSON.parse(text)

  const imageHost = data.imageHost || data.image_host || ""
  const activeKey = data.activeApiKey || data.active_api_key || ""

  if (!activeKey) {
    setKeyStatus("idle", "No active key")
    return
  }

  setKeyUi(imageHost, activeKey)
  setKeyStatus("ok", "Active key ready")
}

document.addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-copy]")
  if (!btn) return
  const id = btn.getAttribute("data-copy")
  const el = document.getElementById(id)
  if (!el) return
  try {
    await navigator.clipboard.writeText(el.value || el.textContent || "")
    const prev = btn.textContent
    btn.textContent = "Copied"
    setTimeout(() => (btn.textContent = prev), 900)
  } catch {
    const prev = btn.textContent
    btn.textContent = "Copy failed"
    setTimeout(() => (btn.textContent = prev), 900)
  }
})

if (uploadFile) {
  uploadFile.addEventListener("change", () => {
    const f = uploadFile.files && uploadFile.files[0]
    fileLabel.textContent = f ? f.name : "Choose an image…"
  })
}

if (logoutBtn) {
  logoutBtn.addEventListener("click", async () => {
    try {
      await fetch("/user/logout", { method: "POST", credentials: "include" })
    } catch {}
    window.location.href = "/user/auth"
  })
}

if (generateBtn) {
  generateBtn.addEventListener("click", async () => {
    try {
      setKeyStatus("busy", "Generating…")

      const name = String(keyNameEl?.value || "").trim() || "user"
      const res = await fetch("/api/user/keys/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name }),
        credentials: "include"
      })

      const text = await res.text()
      if (!res.ok) throw new Error(text || `HTTP ${res.status}`)

      const data = JSON.parse(text)

      const imageHost = data.imageHost || data.image_host || ""
      const newKey = data.apiKey || data.api_key || ""

      if (!newKey) throw new Error("No api key returned from server")

      setKeyUi(imageHost, newKey)
      setKeyStatus("ok", "New key generated")
    } catch (err) {
      setKeyStatus("err", `Failed: ${err?.message || String(err)}`)
    }
  })
}

if (uploadForm) {
  uploadForm.addEventListener("submit", async (e) => {
    e.preventDefault()
    const f = uploadFile.files && uploadFile.files[0]
    if (!f) return

    setStatus("busy", "Uploading…")
    errorBox.classList.add("hidden")

    const fd = new FormData()
    fd.append("file", f)

    try {
      const res = await fetch(`${API_URL}/upload`, { method: "POST", body: fd, credentials: "include" })
      const text = await res.text()
      if (!res.ok) throw new Error(text || `HTTP ${res.status}`)
      const data = JSON.parse(text)
      showResult(data)
    } catch (err) {
      showError(err?.message || String(err))
    }
  })
}

if (fetchForm) {
  fetchForm.addEventListener("submit", async (e) => {
    e.preventDefault()
    const url = (fetchUrl.value || "").trim()
    if (!url) return

    setStatus("busy", "Fetching…")
    errorBox.classList.add("hidden")

    const body = new URLSearchParams()
    body.set("url", url)

    try {
      const res = await fetch(`${API_URL}/fetch`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
        credentials: "include"
      })

      const text = await res.text()
      if (!res.ok) throw new Error(text || `HTTP ${res.status}`)
      const data = JSON.parse(text)
      showResult(data)
    } catch (err) {
      showError(err?.message || String(err))
    }
  })
}

setStatus("idle", "Idle")
loadUserKeys().catch(err => setKeyStatus("err", `Failed: ${err?.message || String(err)}`))

