const API_URL = "/user-image-api"

const page = document.body.getAttribute("data-page") || ""

const apiLabel = document.getElementById("apiLabel")
if (apiLabel) apiLabel.textContent = API_URL

const statusEl = document.getElementById("status")
const keyStatusEl = document.getElementById("keyStatus")
const logoutBtn = document.getElementById("logoutBtn")

const miniAvatar = document.getElementById("miniAvatar")
const avatarFallback = document.getElementById("avatarFallback")
const miniUsername = document.getElementById("miniUsername")

const autoCopyToggle = document.getElementById("autoCopyToggle")
const copyToast = document.getElementById("copyToast")

let toastTimer = null

const PREF_KEY = "mm_autocopy_direct"
function getAutoCopy() {
  const v = localStorage.getItem(PREF_KEY)
  if (v === null) return true
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
  toastTimer = setTimeout(() => copyToast.classList.add("hidden"), 1200)
}

function setStatus(kind, text) {
  if (!statusEl) return
  statusEl.className = `status ${kind}`
  statusEl.textContent = text
}
function setKeyStatus(kind, text) {
  if (!keyStatusEl) return
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

function highlightNav() {
  const links = document.querySelectorAll("[data-nav]")
  for (const a of links) {
    const k = a.getAttribute("data-nav")
    a.classList.toggle("active", k === page)
  }
}

async function loadProfileMini() {
  try {
    const res = await fetch("/api/user/profile", { credentials: "include" })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error("fail")

    const u = data.user || {}
    const username = String(u.username || "")
    const avatar = String(u.avatarDirectUrl || "")

    if (miniUsername) miniUsername.textContent = username || "User"

    const letter = (username || "U").slice(0, 1).toUpperCase()
    if (avatarFallback) avatarFallback.textContent = letter

    if (avatar) {
      if (miniAvatar) {
        miniAvatar.src = avatar
        miniAvatar.classList.remove("hidden")
      }
      if (avatarFallback) avatarFallback.classList.add("hidden")
    } else {
      if (miniAvatar) miniAvatar.removeAttribute("src")
      if (avatarFallback) avatarFallback.classList.remove("hidden")
    }
  } catch {
    if (miniUsername) miniUsername.textContent = "User"
  }
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
    if (id === "directUrl") showToast("Copied direct link")
  } catch {
    btn.textContent = "Copy failed"
    setTimeout(() => (btn.textContent = "Copy"), 900)
  }
})

if (autoCopyToggle) {
  autoCopyToggle.addEventListener("change", () => setAutoCopy(!!autoCopyToggle.checked))
  setAutoCopy(getAutoCopy())
}

if (logoutBtn) {
  logoutBtn.addEventListener("click", async () => {
    try { await fetch("/user/logout", { method: "POST", credentials: "include" }) } catch {}
    sessionStorage.removeItem("active_api_key")
    location.href = "/user/auth"
  })
}

function buildCurl(apiKey) {
  const curlUploadEl = document.getElementById("curlUpload")
  const curlFetchEl = document.getElementById("curlFetch")
  const key = String(apiKey || "").trim()
  if (!curlUploadEl || !curlFetchEl) return
  if (!key) {
    curlUploadEl.value = ""
    curlFetchEl.value = ""
    return
  }
  const base = (location.origin || "").replace(/\/$/, "")
  curlUploadEl.value = `curl -X POST "${base}${API_URL}/upload" -H "Authorization: Bearer ${key}" -F "file=@image.png"`
  curlFetchEl.value = `curl -X POST "${base}${API_URL}/fetch" -H "Authorization: Bearer ${key}" -H "Content-Type: application/x-www-form-urlencoded" --data "url=https%3A%2F%2Fexample.com%2Fimage.png"`
}

async function loadKeyUi() {
  const activeKeyEl = document.getElementById("activeKey")
  if (!activeKeyEl) return
  const cached = sessionStorage.getItem("active_api_key") || ""
  if (cached) {
    activeKeyEl.value = cached
    buildCurl(cached)
    setKeyStatus("ok", "Active key loaded")
  } else {
    activeKeyEl.value = ""
    buildCurl("")
    setKeyStatus("idle", "No active key")
  }
}

async function regenerateKey() {
  const keyNameEl = document.getElementById("keyName")
  const activeKeyEl = document.getElementById("activeKey")
  if (!activeKeyEl) return
  try {
    setKeyStatus("busy", "Regenerating…")
    const name = String(keyNameEl?.value || "user").trim() || "user"

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
}

function safeHref(u) {
  const s = String(u || "").trim()
  return /^https?:\/\//i.test(s) || s.startsWith("/") ? s : "#"
}

async function maybeAutoCopyDirect(url) {
  const on = getAutoCopy()
  const s = String(url || "").trim()
  if (!on || (!/^https?:\/\//i.test(s) && !s.startsWith("/"))) return
  try {
    await navigator.clipboard.writeText(s)
    showToast("Copied direct link")
  } catch {}
}

function showResult(data) {
  const resultEl = document.getElementById("result")
  const errorBox = document.getElementById("errorBox")
  const previewImg = document.getElementById("previewImg")
  const directUrl = document.getElementById("directUrl")
  const pageUrl = document.getElementById("pageUrl")
  const directOpen = document.getElementById("directOpen")
  const pageOpen = document.getElementById("pageOpen")
  const meta = document.getElementById("meta")

  if (!resultEl) return

  if (errorBox) errorBox.classList.add("hidden")
  resultEl.classList.remove("hidden")

  if (directUrl) directUrl.value = data.direct_url || ""
  if (pageUrl) pageUrl.value = data.page_url || ""

  if (directOpen) directOpen.href = safeHref(data.direct_url)
  if (pageOpen) pageOpen.href = safeHref(data.page_url)

  if (previewImg) previewImg.src = data.direct_url || ""

  const bits = []
  if (data.id) bits.push(`id: ${data.id}`)
  if (data.mime) bits.push(`type: ${data.mime}`)
  if (typeof data.size_bytes === "number") bits.push(`size: ${formatBytes(data.size_bytes)}`)
  if (meta) meta.textContent = bits.join(" • ")

  setStatus("ok", "Done")
  maybeAutoCopyDirect(data.direct_url)
}

function showError(msg) {
  const resultEl = document.getElementById("result")
  const errorBox = document.getElementById("errorBox")
  if (resultEl) resultEl.classList.add("hidden")
  if (errorBox) {
    errorBox.classList.remove("hidden")
    errorBox.textContent = String(msg || "Error")
  }
  setStatus("err", "Error")
}

function setProgress(visible, pct, text) {
  const progressWrap = document.getElementById("progressWrap")
  const progressBar = document.getElementById("progressBar")
  const progressText = document.getElementById("progressText")
  if (!progressWrap) return
  progressWrap.classList.toggle("hidden", !visible)
  progressWrap.setAttribute("aria-hidden", visible ? "false" : "true")
  if (progressBar) progressBar.style.width = `${Math.max(0, Math.min(100, pct || 0))}%`
  if (progressText) progressText.textContent = text || ""
}

let activeXhr = null

function cancelActive() {
  if (activeXhr) {
    try { activeXhr.abort() } catch {}
    activeXhr = null
  }
  setProgress(false, 0, "")
  setStatus("idle", "Idle")
}

function uploadViaXhr(file) {
  return new Promise((resolve, reject) => {
    cancelActive()
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
      if (!ev.lengthComputable) return setProgress(true, 20, "Uploading…")
      const now = performance.now()
      const dt = (now - lastT) / 1000
      const dbytes = ev.loaded - lastLoaded
      const speed = dt > 0 ? dbytes / dt : 0
      lastT = now
      lastLoaded = ev.loaded
      const pct = ev.total > 0 ? (ev.loaded / ev.total) * 100 : 0
      setProgress(true, pct, `Uploading… ${pct.toFixed(0)}% • ${formatBytes(ev.loaded)} / ${formatBytes(ev.total)} • ${formatSpeed(speed)}`)
    }

    xhr.onerror = () => { activeXhr = null; setProgress(false, 0, ""); reject(new Error("Network error")) }
    xhr.onabort = () => { activeXhr = null; setProgress(false, 0, ""); reject(new Error("Upload cancelled")) }

    xhr.onload = () => {
      activeXhr = null
      const text = xhr.responseText || ""
      if (xhr.status < 200 || xhr.status >= 300) return reject(new Error(`HTTP ${xhr.status}\n${text}`))
      let data
      try { data = JSON.parse(text) } catch { return reject(new Error(`Expected JSON but got:\n${text}`)) }
      const secs = (performance.now() - t0) / 1000
      const avg = secs > 0 ? (file.size / secs) : 0
      setProgress(false, 0, "")
      setStatus("ok", `Done • avg ${formatSpeed(avg)}`)
      resolve(data)
    }

    xhr.send(fd)
  })
}

function dtHasFiles(dt) {
  if (!dt) return false
  if (dt.files && dt.files.length > 0) return true
  if (dt.items && dt.items.length > 0) {
    for (const it of Array.from(dt.items)) if (it.kind === "file") return true
  }
  const types = Array.from(dt.types || [])
  return types.includes("Files")
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

function initDashboard() {
  const generateKeyBtn = document.getElementById("generateKeyBtn")
  if (generateKeyBtn) generateKeyBtn.addEventListener("click", regenerateKey)
  loadKeyUi()
  setStatus("idle", "Idle")
}

function initUpload() {
  const dropOverlay = document.getElementById("dropOverlay")
  const uploadForm = document.getElementById("uploadForm")
  const uploadFile = document.getElementById("uploadFile")
  const fileLabel = document.getElementById("fileLabel")
  const cancelBtn = document.getElementById("cancelBtn")

  let dragDepth = 0
  let overlayShown = false

  function hardHideDrop() {
    dragDepth = 0
    overlayShown = false
    if (!dropOverlay) return
    dropOverlay.classList.add("hidden")
    dropOverlay.setAttribute("aria-hidden", "true")
    dropOverlay.classList.remove("hot")
  }
  function showDrop(on) {
    if (!dropOverlay) return
    overlayShown = !!on
    dropOverlay.classList.toggle("hidden", !on)
    dropOverlay.setAttribute("aria-hidden", on ? "false" : "true")
    if (!on) dropOverlay.classList.remove("hot")
  }

  if (cancelBtn) cancelBtn.addEventListener("click", () => { cancelActive(); hardHideDrop() })

  if (uploadFile) {
    uploadFile.addEventListener("change", () => {
      const f = uploadFile.files && uploadFile.files[0]
      if (fileLabel) fileLabel.textContent = f ? f.name : "Choose an image…"
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

  document.addEventListener("dragenter", (e) => {
    if (!dtHasFiles(e.dataTransfer)) return
    dragDepth += 1
    if (!overlayShown) showDrop(true)
  }, true)

  document.addEventListener("dragover", (e) => {
    if (!dtHasFiles(e.dataTransfer)) return
    e.preventDefault()
    e.dataTransfer.dropEffect = "copy"
    if (dropOverlay) {
      dropOverlay.classList.add("hot")
      clearTimeout(dropOverlay._hotTimer)
      dropOverlay._hotTimer = setTimeout(() => dropOverlay.classList.remove("hot"), 120)
    }
  }, true)

  document.addEventListener("dragleave", () => {
    dragDepth = Math.max(0, dragDepth - 1)
    if (dragDepth === 0) showDrop(false)
  }, true)

  document.addEventListener("drop", async (e) => {
    if (!dtHasFiles(e.dataTransfer)) return
    e.preventDefault()
    const f = pickFirstFile(e.dataTransfer)
    hardHideDrop()
    if (f) await handleUploadFile(f)
  }, true)

  window.addEventListener("dragend", () => hardHideDrop())
  window.addEventListener("blur", () => hardHideDrop())
  window.addEventListener("focus", () => hardHideDrop())
  document.addEventListener("visibilitychange", () => { if (document.hidden) hardHideDrop() })
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") hardHideDrop() })

  window.addEventListener("paste", async (e) => {
    const f = await fileFromClipboardEvent(e)
    if (!f) return
    await handleUploadFile(f)
  })

  setStatus("idle", "Idle")
}

function initFetch() {
  const fetchForm = document.getElementById("fetchForm")
  const fetchUrl = document.getElementById("fetchUrl")

  if (!fetchForm || !fetchUrl) return

  fetchForm.addEventListener("submit", async (e) => {
    e.preventDefault()
    const v = validateFetchUrl(fetchUrl.value)
    if (!v.ok) return showError(v.error)

    setStatus("busy", "Fetching…")
    const body = new URLSearchParams()
    body.set("url", v.value)

    try {
      setProgress(true, 20, v.warn ? v.warn : "Fetching image…")
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

  setStatus("idle", "Idle")
}

function showMsg(el, kind, text) {
  if (!el) return
  el.className = `msg ${kind}`
  el.textContent = text || ""
  el.classList.toggle("hidden", !text)
}

async function loadProfileFull() {
  const profileAvatarImg = document.getElementById("profileAvatarImg")
  const profileAvatarFallback = document.getElementById("profileAvatarFallback")
  const newUsername = document.getElementById("newUsername")
  try {
    const res = await fetch("/api/user/profile", { credentials: "include" })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error("fail")
    const u = data.user || {}
    const username = String(u.username || "")
    const avatar = String(u.avatarDirectUrl || "")
    if (newUsername) newUsername.value = username || ""
    const letter = (username || "U").slice(0, 1).toUpperCase()
    if (profileAvatarFallback) profileAvatarFallback.textContent = letter
    if (avatar) {
      if (profileAvatarImg) profileAvatarImg.src = avatar
      if (profileAvatarFallback) profileAvatarFallback.classList.add("hidden")
    } else {
      if (profileAvatarImg) profileAvatarImg.removeAttribute("src")
      if (profileAvatarFallback) profileAvatarFallback.classList.remove("hidden")
    }
  } catch {}
}

async function uploadAvatar(file) {
  const fd = new FormData()
  fd.append("file", file, file.name || "avatar")
  const res = await fetch(`${API_URL}/upload`, { method: "POST", body: fd, credentials: "include" })
  const text = await res.text()
  if (!res.ok) throw new Error(text || `HTTP ${res.status}`)
  const data = JSON.parse(text)
  const direct = String(data.direct_url || "")
  const pageUrl = String(data.page_url || "")

  const save = await fetch("/api/user/profile/avatar", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ avatarDirectUrl: direct, avatarPageUrl: pageUrl })
  })
  const saveData = await save.json().catch(() => ({}))
  if (!save.ok) throw new Error(String(saveData.error || "Failed to save avatar"))
  await loadProfileMini()
  await loadProfileFull()
}

function initProfile() {
  const avatarFile = document.getElementById("avatarFile")
  const removeAvatarBtn = document.getElementById("removeAvatarBtn")
  const usernameForm = document.getElementById("usernameForm")
  const newUsername = document.getElementById("newUsername")
  const usernameMsg = document.getElementById("usernameMsg")
  const passwordForm = document.getElementById("passwordForm")
  const currentPassword = document.getElementById("currentPassword")
  const newPassword = document.getElementById("newPassword")
  const passwordMsg = document.getElementById("passwordMsg")
  const togglePwBtn = document.getElementById("togglePwBtn")

  if (togglePwBtn && currentPassword && newPassword) {
    togglePwBtn.addEventListener("click", () => {
      const t = newPassword.type === "password" ? "text" : "password"
      newPassword.type = t
      currentPassword.type = t
      togglePwBtn.textContent = t === "text" ? "Hide" : "Show"
    })
  }

  if (avatarFile) {
    avatarFile.addEventListener("change", async () => {
      const f = avatarFile.files && avatarFile.files[0]
      if (!f) return
      try {
        setStatus("busy", "Uploading avatar…")
        await uploadAvatar(f)
        setStatus("ok", "Avatar updated")
      } catch (err) {
        showError(err?.message || String(err))
      } finally {
        avatarFile.value = ""
      }
    })
  }

  if (removeAvatarBtn) {
    removeAvatarBtn.addEventListener("click", async () => {
      try {
        const res = await fetch("/api/user/profile/avatar/remove", { method: "POST", credentials: "include" })
        const data = await res.json().catch(() => ({}))
        if (!res.ok) throw new Error(String(data.error || "Failed"))
        await loadProfileMini()
        await loadProfileFull()
      } catch (err) {
        showError(err?.message || String(err))
      }
    })
  }

  if (usernameForm && newUsername) {
    usernameForm.addEventListener("submit", async (e) => {
      e.preventDefault()
      showMsg(usernameMsg, "", "")
      const u = String(newUsername.value || "").trim()
      if (u.length < 3 || u.length > 32) return showMsg(usernameMsg, "err", "Username must be 3–32 characters")
      try {
        const res = await fetch("/api/user/profile/username", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ username: u })
        })
        const data = await res.json().catch(() => ({}))
        if (!res.ok) throw new Error(String(data.error || "Failed"))
        showMsg(usernameMsg, "ok", "Username updated")
        await loadProfileMini()
        await loadProfileFull()
      } catch (err) {
        showMsg(usernameMsg, "err", err?.message || "Failed")
      }
    })
  }

  if (passwordForm && currentPassword && newPassword) {
    passwordForm.addEventListener("submit", async (e) => {
      e.preventDefault()
      showMsg(passwordMsg, "", "")
      const cur = String(currentPassword.value || "")
      const nxt = String(newPassword.value || "")
      if (!cur) return showMsg(passwordMsg, "err", "Enter your current password")
      if (nxt.length < 8) return showMsg(passwordMsg, "err", "New password must be at least 8 characters")
      try {
        const res = await fetch("/api/user/profile/password", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ currentPassword: cur, newPassword: nxt })
        })
        const data = await res.json().catch(() => ({}))
        if (!res.ok) throw new Error(String(data.error || "Failed"))
        currentPassword.value = ""
        newPassword.value = ""
        showMsg(passwordMsg, "ok", "Password updated")
      } catch (err) {
        showMsg(passwordMsg, "err", err?.message || "Failed")
      }
    })
  }

  loadProfileFull()
  setStatus("idle", "Idle")
}

highlightNav()
loadProfileMini()

if (page === "dashboard") initDashboard()
if (page === "upload") initUpload()
if (page === "fetch") initFetch()
if (page === "profile") initProfile()

const generateKeyBtn = document.getElementById("generateKeyBtn")
if (generateKeyBtn) generateKeyBtn.addEventListener("click", regenerateKey)

loadKeyUi()
setAutoCopy(getAutoCopy())
