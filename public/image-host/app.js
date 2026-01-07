document.addEventListener("DOMContentLoaded", () => {
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

  const keyNameEl = document.getElementById("keyName")
  const genBtn = document.getElementById("generateKeyBtn")
  const keyStatus = document.getElementById("keyStatus")
  const activeKeyEl = document.getElementById("activeKey")
  const curlUpload = document.getElementById("curlUpload")
  const curlFetch = document.getElementById("curlFetch")
  const logoutBtn = document.getElementById("logoutBtn")

  if (apiLabel) apiLabel.textContent = API_URL

  function setStatus(kind, text) {
    if (!statusEl) return
    statusEl.className = `status ${kind}`
    statusEl.textContent = text
  }

  function setKeyStatus(kind, text) {
    if (!keyStatus) return
    keyStatus.className = `status ${kind}`
    keyStatus.textContent = text
  }

  function showError(err) {
    if (resultEl) resultEl.classList.add("hidden")
    if (errorBox) {
      errorBox.classList.remove("hidden")
      errorBox.textContent = typeof err === "string" ? err : JSON.stringify(err, null, 2)
    }
    setStatus("err", "Error")
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

  function showResult(data) {
    if (errorBox) errorBox.classList.add("hidden")
    if (resultEl) resultEl.classList.remove("hidden")

    if (directUrl) directUrl.value = data.direct_url || ""
    if (pageUrl) pageUrl.value = data.page_url || ""

    if (directOpen) directOpen.href = data.direct_url || "#"
    if (pageOpen) pageOpen.href = data.page_url || "#"

    if (previewImg) previewImg.src = data.direct_url || ""

    const bits = []
    if (data.id) bits.push(`id: ${data.id}`)
    if (data.mime) bits.push(`type: ${data.mime}`)
    if (typeof data.size_bytes === "number") bits.push(`size: ${formatBytes(data.size_bytes)}`)
    if (meta) meta.textContent = bits.join(" • ")

    setStatus("ok", "Done")
  }

  document.addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-copy]")
    if (!btn) return
    const id = btn.getAttribute("data-copy")
    const el = document.getElementById(id)
    if (!el) return
    const val = el.value || el.textContent || ""
    try {
      await navigator.clipboard.writeText(val)
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
      if (fileLabel) fileLabel.textContent = f ? f.name : "Choose an image…"
    })
  }

  function buildCurlUpload(host, apiKey) {
    return `curl -i -X POST "${host}/upload" -H "Authorization: Bearer ${apiKey}" -F "file=@C:\\path\\to\\image.png"`
  }

  function buildCurlFetch(host, apiKey) {
    return `curl -i -X POST "${host}/fetch" -H "Authorization: Bearer ${apiKey}" -H "Content-Type: application/x-www-form-urlencoded" --data "url=https://example.com/image.png"`
  }

  async function refreshKeys() {
    try {
      setKeyStatus("busy", "Loading…")
      const res = await fetch("/api/user/keys", { credentials: "include" })
      const text = await res.text()
      let data
      try { data = JSON.parse(text) } catch { data = { error: text } }
      if (!res.ok) throw new Error(data?.error ? JSON.stringify(data.error) : `HTTP ${res.status}`)

      const activeKeyId = data.activeKeyId || ""
      const keys = Array.isArray(data.keys) ? data.keys : []
      const active = keys.find(k => k.keyId === activeKeyId) || null

      if (activeKeyEl) activeKeyEl.value = active?.apiKey || ""
      if (curlUpload) curlUpload.value = active?.apiKey ? buildCurlUpload(location.origin, active.apiKey) : ""
      if (curlFetch) curlFetch.value = active?.apiKey ? buildCurlFetch(location.origin, active.apiKey) : ""

      setKeyStatus(active?.apiKey ? "ok" : "idle", active?.apiKey ? "Active key ready" : "No active key")
    } catch (err) {
      setKeyStatus("err", `Failed: ${err?.message || String(err)}`)
    }
  }

  async function createKey() {
    try {
      setKeyStatus("busy", "Generating…")
      const name = (keyNameEl?.value || "").trim() || "user"

      const res = await fetch("/api/user/keys/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ name })
      })

      const text = await res.text()
      let data
      try { data = JSON.parse(text) } catch { data = { error: text } }
      if (!res.ok) throw new Error(data?.error ? JSON.stringify(data.error) : `HTTP ${res.status}`)

      await refreshKeys()
    } catch (err) {
      setKeyStatus("err", `Failed: ${err?.message || String(err)}`)
    }
  }

  if (genBtn) genBtn.addEventListener("click", createKey)

  if (logoutBtn) {
    logoutBtn.addEventListener("click", async (e) => {
      e.preventDefault()
      try {
        await fetch("/user/logout", { method: "POST", credentials: "include" })
      } catch {}
      window.location.href = "/user/auth"
    })
  }

  if (uploadForm) {
    uploadForm.addEventListener("submit", async (e) => {
      e.preventDefault()
      const f = uploadFile?.files && uploadFile.files[0]
      if (!f) return

      setStatus("busy", "Uploading…")
      if (errorBox) errorBox.classList.add("hidden")

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
      const url = (fetchUrl?.value || "").trim()
      if (!url) return

      setStatus("busy", "Fetching…")
      if (errorBox) errorBox.classList.add("hidden")

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
  refreshKeys()
})
