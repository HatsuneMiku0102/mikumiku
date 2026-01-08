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

apiLabel.textContent = API_URL

let activeXhr = null

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
}

function setProgress(visible, pct, text) {
  if (!progressWrap) return
  progressWrap.classList.toggle("hidden", !visible)
  progressWrap.setAttribute("aria-hidden", visible ? "false" : "true")
  if (progressBar) progressBar.style.width = `${Math.
