const API_URL = "/user-image-api"

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

const keyStatusEl = document.getElementById("keyStatus")
const keyNameEl = document.getElementById("keyName")
const activeKeyEl = document.getElementById("activeKey")
const curlUploadEl = document.getElementById("curlUpload")
const curlFetchEl = document.getElementById("curlFetch")
const generateKeyBtn = document.getElementById("generateKeyBtn")
const logoutBtn = document.getElementById("logoutBtn")

const dropOverlay = document.getElementById("dropOverlay")
const progressWrap = document.getElementById("progressWrap")
const progressBar = document.getElementById("progressBar")
const progressText = document.getElementById("progressText")
const cancelBtn = document.getElementById("cancelBtn")

const autoCopyToggle = document.getElementById("autoCopyToggle")
const copyToast = document.getElementById("copyToast")

apiLabel.textContent = API_URL

let activeXhr = null
let dragDepth = 0
let toastTimer = null

const PREF_KEY = "mm_autocopy_direct"
const autoCopyDefault = true

function getAutoCopy() {
  const v = localStorage.getItem(PREF_KEY)
  if (v === null) return autoCopyDefault
  return v === "1"
}

function setAutoCopy(on) {
  localStorage.setItem(PREF_KEY, on ? "1" : "0")
  if (autoCopyToggle) autoCopyToggle.checked = !!on
}

function showToast(text) {
  if (!copyToast) return
  copyToast.textContent = text || "Copied"
  copyToast.classList.remove("hidden")
  clearTimeout(toastTimer)
  toastTimer = setTimeout(() => copyToast.classList.add("hidden"), 1300)
}

function setStatus(kind, text) {
  statusEl.className = `status ${kind}`
  statusEl.textContent = text
}

function setKeyStatus(kind, text) {
  keyStatusEl.className = `status ${kind}`
  keyStatusEl.textContent = text
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

function formatSpeed(bps) {
  if (!Number.isFinite(bps) || bps <= 0) return ""
  return `${formatBytes(bps)}/s`
}

function showError(err) {
  resultEl.classList.add("hidden")
  errorBox.classList.remove("hidden")
  errorBox.textContent = typeof err === "string" ? err : JSON.stringify(err, null, 2)
  setStatus("err", "Error")
}

function safeHref(u) {
  const s = String(u || "").trim()
  return /^https?:\/\//i.test(s) ? s : "#"
}

async function maybeAutoCopyDirect(url) {
  const on = getAutoCopy()
  const s = String(url || "").trim()
  if (!on || !/^https?:\/\//i.test(s)) return
  try {
    await navigator.clipboard.writeText(s)
    showToast("Copied direct link")
  } catch {
    showToast("Copy blocked by browser")
  }
}

function showResult(data) {
  errorBox.classList.add("hidden")
  resultEl.classList.remove("hidden")

  directUrl.value = data.direct_url || ""
  pageUrl.value = data.page_url || ""

  directOpen.href = safeHref(data.direct_url)
  pageOpen.href = safeHref(data.page_url)

  previewImg.src = data.direct_url || ""

  const bits = []
  if (data.id) bits.push(`id: ${data.id}`)
  if (data.mime) bits.push(`type: ${data.mime}`)
  if (typeof data.size_bytes === "number") bits.push(`size: ${formatBytes(data.size_bytes)}`)
  meta.textContent = bits.join(" • ")

  setStatus("ok", "Done")
  maybeAutoCopyDirect(data.direct_url)
}

function setProgress(visible, pct, text) {
  if (!progressWrap) return
  progressWrap.classList.toggle("hidden", !visible)
  progressWrap.setAttribute("aria-hidden", visible ? "false" : "true")
  if (progressBar) progressBar.style.width = `${Math.max(0, Math.min(100, pct || 0))}%`
  if (progressText) progressText.textContent = text || ""
}

function showDrop(on) {
  if (!dropOverlay) return
  dropOverlay.classList.toggle("hidden", !on)
  dropOverlay.setAttribute("aria-hidden", on ? "false" : "true")
  document.body.classList.toggle("dropping", !!on)
}

function cancelActive() {
  if (activeXhr) {
    try { activeXhr.abort() } catch {}
    activeXhr = null
  }
  setProgress(false, 0, "")
  setStatus("idle", "Idle")
}

if (cancelBtn) cancelBtn.addEventListener("click", () => cancelActive())

function buildCurl(apiKey) {
  const key = String(apiKey || "").trim()
  if (!key) {
    curlUploadEl.value = ""
    curlFetchEl.value = ""
    return
  }
  const base = (location.origin || "").replace(/\/$/, "")
  curlUploadEl.value = `curl -X POST "${base}${API_URL}/upload" -H "Authorization: Bearer ${key}" -F "file=@image.png"`
  curlFetchEl.value = `curl -X POST "${base}${API_URL}/fetch" -H "Authorization: Bearer ${key}" -H "Content-Type: application/x-www-form-urlencoded" --data "url=https%3A%2F%2Fexample.com%2Fimage.png"`
}

document.addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-copy]")
  if (!btn) return
  const id = btn.getAttribute("data-copy")
  const el = document.getElementById(id)
  if (!el) return
  try {
    await navigator.clipboard.writeText(el.value || "")
    btn.textContent = "Copied"
    setTimeout(() => (btn.textContent = "Copy"), 900)
  } catch {
    btn.textContent = "Copy failed"
    setTimeout(() => (btn.textContent = "Copy"), 900)
  }
})

if (autoCopyToggle) {
  autoCopyToggle.addEventListener("change", () => setAutoCopy(!!autoCopyToggle.checked))
  setAutoCopy(getAutoCopy())
}

if (uploadFile) {
  uploadFile.addEventListener("change", () => {
    const f = uploadFile.files && uploadFile.files[0]
    fileLabel.textContent = f ? f.name : "Choose an image…"
  })
}

function isProbablyDirectImageUrl(u) {
  const s = String(u || "").trim().toLowerCase()
  return /\.(png|jpe?g|gif|webp)(\?|#|$)/i.test(s)
}

function validateFetchUrl(raw) {
  const s = String(raw || "").trim()
  if (!s) return { ok: false, error: "Enter a URL." }
  if (s.length > 2048) return { ok: false, error: "URL is too long." }
  let url
  try { url = new URL(s) } catch { return { ok: false, error: "Invalid URL." } }
  if (!/^https?:$/i.test(url.protocol)) return { ok: false, error: "Only http/https URLs are allowed." }
  if (!url.hostname) return { ok: false, error: "URL host is missing." }
  const warn = isProbablyDirectImageUrl(s) ? "" : "This doesn’t look like a direct image link. It may fail unless it resolves to an image file."
  return { ok: true, value: s, warn }
}

function uploadViaXhr(file) {
  return new Promise((resolve, reject) => {
    cancelActive()
    resultEl.classList.add("hidden")
    errorBox.classList.add("hidden")

    const fd = new FormData()
    fd.append("file", file, file.name || "image")

    const xhr = new XMLHttpRequest()
    activeXhr = xhr

    const t0 = performance.now()
    let lastT = t0
    let lastLoaded = 0

    setStatus("busy", "Uploading…")
    setProgress(true, 1, "Starting upload…")

    xhr.open("POST", `${API_URL}/upload`, true)
    xhr.withCredentials = true

    xhr.upload.onprogress = (ev) => {
      if (!ev.lengthComputable) {
        setProgress(true, 20, "Uploading…")
        return
      }

      const now = performance.now()
      const dt = (now - lastT) / 1000
      const dbytes = ev.loaded - lastLoaded
      const speed = dt > 0 ? dbytes / dt : 0

      lastT = now
      lastLoaded = ev.loaded

      const pct = ev.total > 0 ? (ev.loaded / ev.total) * 100 : 0
      const label = `Uploading… ${pct.toFixed(0)}% • ${formatBytes(ev.loaded)} / ${formatBytes(ev.total)} • ${formatSpeed(speed)}`
      setProgress(true, pct, label)
    }

    xhr.onerror = () => {
      activeXhr = null
      setProgress(false, 0, "")
      reject(new Error("Network error"))
    }

    xhr.onabort = () => {
      activeXhr = null
      setProgress(false, 0, "")
      reject(new Error("Upload cancelled"))
    }

    xhr.onload = () => {
      activeXhr = null
      const text = xhr.responseText || ""
      if (xhr.status < 200 || xhr.status >= 300) {
        setProgress(false, 0, "")
        reject(new Error(`HTTP ${xhr.status}\n${text}`))
        return
      }

      let data
      try { data = JSON.parse(text) } catch { reject(new Error(`Expected JSON but got:\n${text}`)); return }

      const t1 = performance.now()
      const secs = (t1 - t0) / 1000
      const avg = secs > 0 ? (file.size / secs) : 0
      setProgress(false, 0, "")
      setStatus("ok", `Done • avg ${formatSpeed(avg)}`)

      resolve(data)
    }

    xhr.send(fd)
  })
}

async function handleUploadFile(file) {
  if (!file) return
  if (!file.type || !file.type.startsWith("image/")) return showError("That doesn’t look like an image file.")
  try {
    const data = await uploadViaXhr(file)
    showResult(data)
  } catch (err) {
    showError(err?.message || String(err))
  }
}

if (uploadForm) {
  uploadForm.addEventListener("submit", async (e) => {
    e.preventDefault()
    const f = uploadFile.files && uploadFile.files[0]
    if (!f) return
    await handleUploadFile(f)
  })
}

if (fetchForm) {
  fetchForm.addEventListener("submit", async (e) => {
    e.preventDefault()
    const v = validateFetchUrl(fetchUrl.value)
    if (!v.ok) return showError(v.error)

    setStatus("busy", "Fetching…")
    resultEl.classList.add("hidden")

    if (v.warn) {
      errorBox.classList.remove("hidden")
      errorBox.textContent = v.warn
    } else {
      errorBox.classList.add("hidden")
    }

    const body = new URLSearchParams()
    body.set("url", v.value)

    try {
      setProgress(true, 20, "Fetching image…")
      const res = await fetch(`${API_URL}/fetch`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
        credentials: "include"
      })

      const text = await res.text()
      if (!res.ok) throw new Error(`HTTP ${res.status}\n${text}`)
      let data
      try { data = JSON.parse(text) } catch { throw new Error(`Expected JSON but got:\n${text}`) }
      setProgress(false, 0, "")
      showResult(data)
    } catch (err) {
      setProgress(false, 0, "")
      showError(err?.message || String(err))
    }
  })
}

function dtHasFiles(dt) {
  if (!dt) return false
  if (dt.files && dt.files.length > 0) return true
  if (dt.items && dt.items.length > 0) {
    for (const it of Array.from(dt.items)) if (it.kind === "file") return true
  }
  return false
}

function pickFirstFile(dt) {
  if (!dt) return null
  if (dt.files && dt.files.length) return dt.files[0]
  if (dt.items && dt.items.length) {
    for (const it of Array.from(dt.items)) {
      if (it.kind === "file") {
        const f = it.getAsFile && it.getAsFile()
        if (f) return f
      }
    }
  }
  return null
}

const dragTargets = [document, document.body, dropOverlay].filter(Boolean)

for (const t of dragTargets) {
  t.addEventListener("dragenter", (e) => {
    if (!dtHasFiles(e.dataTransfer)) return
    dragDepth += 1
    showDrop(true)
  })
  t.addEventListener("dragover", (e) => {
    if (!dtHasFiles(e.dataTransfer)) return
    e.preventDefault()
    e.dataTransfer.dropEffect = "copy"
    if (dropOverlay) dropOverlay.classList.add("hot")
    clearTimeout(t._hotTimer)
    t._hotTimer = setTimeout(() => dropOverlay && dropOverlay.classList.remove("hot"), 120)
  })
  t.addEventListener("dragleave", () => {
    dragDepth = Math.max(0, dragDepth - 1)
    if (dragDepth === 0) showDrop(false)
  })
  t.addEventListener("drop", async (e) => {
    if (!dtHasFiles(e.dataTransfer)) return
    e.preventDefault()
    showDrop(false)
    dragDepth = 0
    const f = pickFirstFile(e.dataTransfer)
    if (f) await handleUploadFile(f)
  })
}

async function fileFromClipboardEvent(e) {
  const dt = e.clipboardData
  if (dt) {
    const items = Array.from(dt.items || [])
    for (const it of items) {
      if (it.kind === "file" && String(it.type || "").startsWith("image/")) {
        const f = it.getAsFile && it.getAsFile()
        if (f) return f
      }
    }
  }

  if (navigator.clipboard && navigator.clipboard.read) {
    try {
      const items2 = await navigator.clipboard.read()
      for (const item of items2) {
        for (const type of item.types || []) {
          if (String(type).startsWith("image/")) {
            const blob = await item.getType(type)
            return new File([blob], "clipboard-image", { type: blob.type || type })
          }
        }
      }
    } catch {}
  }

  return null
}

window.addEventListener("paste", async (e) => {
  const f = await fileFromClipboardEvent(e)
  if (!f) return
  await handleUploadFile(f)
})

async function loadKeyUi() {
  const cached = sessionStorage.getItem("active_api_key") || ""
  if (cached) {
    activeKeyEl.value = cached
    buildCurl(cached)
    setKeyStatus("ok", "Active key loaded")
    return
  }
  activeKeyEl.value = ""
  buildCurl("")
  setKeyStatus("idle", "No active key")
}

if (generateKeyBtn) {
  generateKeyBtn.addEventListener("click", async () => {
    try {
      setKeyStatus("busy", "Generating…")
      const name = String(keyNameEl.value || "user").trim() || "user"

      const res = await fetch("/api/user/keys/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ name })
      })

      const text = await res.text()
      if (!res.ok) throw new Error(text || `HTTP ${res.status}`)

      const data = JSON.parse(text || "{}")
      const apiKey = String(data.apiKey || data.api_key || "").trim()
      if (!apiKey) throw new Error("No api key returned from server")

      activeKeyEl.value = apiKey
      sessionStorage.setItem("active_api_key", apiKey)
      buildCurl(apiKey)
      setKeyStatus("ok", "Active key set")
    } catch (err) {
      setKeyStatus("err", `Failed: ${err?.message || String(err)}`)
    }
  })
}

if (logoutBtn) {
  logoutBtn.addEventListener("click", async () => {
    try { await fetch("/user/logout", { method: "POST", credentials: "include" }) } catch {}
    sessionStorage.removeItem("active_api_key")
    location.href = "/user/auth"
  })
}

setStatus("idle", "Idle")
setProgress(false, 0, "")
setAutoCopy(getAutoCopy())
loadKeyUi()
