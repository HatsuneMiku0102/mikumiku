'use strict'

const express = require('express')
const http = require('http')
const socketIo = require('socket.io')
const bcrypt = require('bcryptjs')
const session = require('express-session')
const path = require('path')
const dotenv = require('dotenv')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const axios = require('axios')
const MongoStore = require('connect-mongo')
const helmet = require('helmet')
const mongoose = require('mongoose')
const winston = require('winston')
const { body, validationResult } = require('express-validator')
const cors = require('cors')
const rateLimit = require('express-rate-limit')
const OpenAI = require('openai')
const { MongoClient } = require('mongodb')
const nacl = require('tweetnacl')
const os = require('os')
const crypto = require('crypto')
const { createProxyMiddleware, responseInterceptor } = require('http-proxy-middleware')

dotenv.config()

const DISCORD_PUBLIC_KEY = process.env.DISCORD_PUBLIC_KEY || ''
const OPENWEATHER_API_KEY = process.env.OPENWEATHER_API_KEY || ''
const BOT_TOKEN = process.env.BOT_TOKEN || ''
const PORT = process.env.PORT || 3000

const IMAGE_API_TARGET = (process.env.IMAGE_API_TARGET || 'https://image-host-bde701503cb6.herokuapp.com').trim()
const IMAGE_API_KEY = (process.env.IMAGE_API_KEY || '').trim()
const IMAGE_HOST_ADMIN_TARGET = (process.env.IMAGE_HOST_ADMIN_TARGET || '').trim()
const IMAGE_HOST_ADMIN_SECRET = (process.env.IMAGE_HOST_ADMIN_SECRET || '').trim()

const JWT_SECRET = (process.env.JWT_SECRET || '').trim()
if (!JWT_SECRET) {
  console.error('JWT_SECRET is not set.')
  process.exit(1)
}

const mongoUrl = process.env.MONGO_URL
if (!mongoUrl) {
  console.error('MONGO_URL is not set.')
  process.exit(1)
}

const API_KEY_ENC_SECRET = (process.env.API_KEY_ENC_SECRET || '').trim()
if (!API_KEY_ENC_SECRET) {
  console.error('API_KEY_ENC_SECRET is not set.')
  process.exit(1)
}

const BLIZZARD_CLIENT_ID = String(process.env.BLIZZARD_CLIENT_ID || '').trim()
const BLIZZARD_CLIENT_SECRET = String(process.env.BLIZZARD_CLIENT_SECRET || '').trim()
const BLIZZARD_REDIRECT_URI = String(process.env.BLIZZARD_REDIRECT_URI || 'https://mikumiku.dev/oauth/callback').trim()
const BLIZZARD_REGION = String(process.env.BLIZZARD_REGION || 'eu').trim().toLowerCase()
const WOW_LOCALE = String(process.env.WOW_LOCALE || 'en_GB').trim()

const BLIZZARD_AUTHORIZE = 'https://oauth.battle.net/authorize'
const BLIZZARD_TOKEN = 'https://oauth.battle.net/token'

const app = express()
app.set('trust proxy', true)

const server = http.createServer(app)
const io = socketIo(server, { cors: { origin: true, methods: ['GET', 'POST'], allowedHeaders: ['*'], credentials: true } })

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => `${timestamp} [${level.toUpperCase()}]: ${message}`)
  ),
  transports: [new winston.transports.Console(), new winston.transports.File({ filename: 'server.log' })]
})

app.use(cors({
  origin: true,
  methods: ['GET', 'POST', 'OPTIONS', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'x-admin-secret', 'X-Admin-Secret'],
  credentials: true
}))

app.use(express.json({
  verify: (req, _res, buf) => {
    if (req.path === '/interactions') req.rawBody = buf.toString()
  }
}))
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())

app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: [
      "'self'",
      "'unsafe-inline'",
      'https://fonts.googleapis.com',
      'https://cdnjs.cloudflare.com',
      'https://www.youtube.com',
      'https://www.youtube-nocookie.com',
      'https://unpkg.com',
      'https://cdn.jsdelivr.net',
      'https://cdn.skypack.dev',
      'https://cdn.socket.io',
      'https://api.mapbox.com'
    ],
    styleSrc: [
      "'self'",
      "'unsafe-inline'",
      'https://fonts.googleapis.com',
      'https://cdnjs.cloudflare.com',
      'https://api.mapbox.com'
    ],
    imgSrc: [
      "'self'",
      "blob:",
      "data:",
      "https://mikumiku.dev",
      "https://www.mikumiku.dev",
      "http://localhost:3000",
      "http://localhost:8000",
      "https://i.ytimg.com",
      "https://img.youtube.com",
      "https://ytimg.com",
      "https://openweathermap.org",
      "https://i.postimg.cc",
      "https://threejs.org",
      "https://www.youtube.com",
      "https://www.youtube-nocookie.com",
      "https://raw.githubusercontent.com",
      "https://api.tiles.mapbox.com",
      "https://*.tiles.mapbox.com",
      "https://raider.io",
      "https://render.worldofwarcraft.com",
      "https://images.mikumiku.dev"
    ],
    fontSrc: [
      "'self'",
      'https://fonts.gstatic.com',
      'https://cdnjs.cloudflare.com'
    ],
    connectSrc: [
      "'self'",
      'blob:',
      'https://www.googleapis.com',
      'https://*.youtube.com',
      'https://www.youtube-nocookie.com',
      'https://*.ytimg.com',
      'https://api.openweathermap.org',
      'https://cdn.socket.io',
      'https://cdnjs.cloudflare.com',
      'https://cdn.jsdelivr.net',
      'https://mikumiku.dev',
      'https://api.mapbox.com',
      'https://events.mapbox.com',
      'https://mikumikudev-c530e6b3e669.herokuapp.com',
      'https://raider.io',
      'https://oauth.battle.net',
      'https://*.api.blizzard.com',
      'https://images.mikumiku.dev'
    ],
    frameSrc: [
      "'self'",
      'https://discord.com',
      'https://www.youtube.com',
      'https://www.youtube-nocookie.com'
    ],
    mediaSrc: [
      "'self'",
      'https://www.youtube.com',
      'https://www.youtube-nocookie.com'
    ],
    frameAncestors: [
      "'self'",
      'https://discord.com'
    ],
    workerSrc: [
      "'self'",
      'blob:'
    ],
    upgradeInsecureRequests: []
  }
}))

mongoose.connect(mongoUrl)
  .then(() => { logger.info('Connected to MongoDB') })
  .catch((err) => { logger.error(`Error connecting to MongoDB: ${err}`); process.exit(1) })

function sha256Hex(s) {
  return crypto.createHash('sha256').update(String(s)).digest('hex')
}

function encKey() {
  return crypto.createHash('sha256').update(API_KEY_ENC_SECRET).digest()
}

function encryptString(plain) {
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', encKey(), iv)
  const c1 = cipher.update(String(plain), 'utf8')
  const c2 = cipher.final()
  const tag = cipher.getAuthTag()
  return Buffer.concat([iv, tag, c1, c2]).toString('base64')
}

function decryptString(enc) {
  const raw = Buffer.from(String(enc), 'base64')
  const iv = raw.subarray(0, 12)
  const tag = raw.subarray(12, 28)
  const data = raw.subarray(28)
  const decipher = crypto.createDecipheriv('aes-256-gcm', encKey(), iv)
  decipher.setAuthTag(tag)
  const p1 = decipher.update(data)
  const p2 = decipher.final()
  return Buffer.concat([p1, p2]).toString('utf8')
}

const userApiKeySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  keyId: { type: String, required: true, index: true },
  apiKeyEnc: { type: String, required: true },
  keyHash: { type: String, required: true, index: true },
  name: { type: String, default: 'user' },
  scopes: { type: [String], default: ['upload', 'fetch'] },
  ratePerMinute: { type: Number, default: 30 },
  createdAt: { type: Date, default: Date.now }
})
userApiKeySchema.index({ userId: 1, keyId: 1 }, { unique: true })
const UserApiKey = mongoose.model('UserApiKey', userApiKeySchema, 'user_api_keys')

const userSettingsSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, unique: true },
  activeKeyId: { type: String, default: '' },
  avatarDirectUrl: { type: String, default: '' },
  avatarPageUrl: { type: String, default: '' },
  updatedAt: { type: Date, default: Date.now }
})
const UserSettings = mongoose.model('UserSettings', userSettingsSchema, 'user_settings')

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, minlength: 3, maxlength: 32 },
  passwordHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
})
const User = mongoose.model('User', userSchema, 'users')

const GeoDataSchema = new mongoose.Schema({
  ip: { type: String, required: true, unique: true },
  city: { type: String, default: 'Unknown' },
  region: { type: String, default: 'Unknown' },
  country: { type: String, default: 'Unknown' },
  timestamp: { type: Date, default: Date.now }
})
const GeoData = mongoose.model('GeoData', GeoDataSchema, 'geodatas')

const sessionSchema = new mongoose.Schema({
  state: { type: String, required: true, unique: true },
  user_id: { type: String, required: true },
  session_id: { type: String, required: true },
  created_at: { type: Date, default: Date.now, expires: 86400 },
  ip_address: { type: String },
  user_agent: { type: String }
})
mongoose.model('Session', sessionSchema, 'sessions')
const Session = mongoose.model('Session')

const adminSessionStore = MongoStore.create({
  mongoUrl,
  collectionName: 'admin_sessions',
  ttl: 14 * 24 * 60 * 60
})

app.use(session({
  name: 'admin_session_cookie',
  secret: process.env.SESSION_SECRET || 'your-session-secret',
  resave: false,
  saveUninitialized: false,
  store: adminSessionStore,
  cookie: { secure: process.env.NODE_ENV === 'production', httpOnly: true, sameSite: 'strict', maxAge: 60 * 60 * 1000 }
}))

function signAuthToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' })
}

function readJwt(req) {
  const token = req.cookies.token
  if (!token) return null
  try { return jwt.verify(token, JWT_SECRET) } catch { return null }
}

function verifyTokenApi(req, res, next) {
  if (req.method === 'OPTIONS') return res.sendStatus(204)
  const decoded = readJwt(req)
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' })
  req.auth = decoded
  next()
}

function verifyTokenPage(redirectTo) {
  return (req, res, next) => {
    const decoded = readJwt(req)
    if (!decoded) return res.redirect(redirectTo)
    req.auth = decoded
    next()
  }
}

function requireAdminApi(req, res, next) {
  if (!req.auth || req.auth.role !== 'admin') return res.status(403).json({ error: 'Forbidden' })
  next()
}

function requireAdminPage(req, res, next) {
  if (!req.auth || req.auth.role !== 'admin') return res.redirect('/auth')
  next()
}

function requireUserApi(req, res, next) {
  if (!req.auth || (req.auth.role !== 'user' && req.auth.role !== 'admin')) return res.status(403).json({ error: 'Forbidden' })
  next()
}

function requireUserPage(req, res, next) {
  const decoded = readJwt(req)
  if (!decoded || (decoded.role !== 'user' && decoded.role !== 'admin')) return res.redirect('/user/auth')
  req.auth = decoded
  next()
}

async function getActiveUserKeyDoc(decoded) {
  const userId = new mongoose.Types.ObjectId(String(decoded.userId))
  const settings = await UserSettings.findOne({ userId }).lean()
  if (!settings?.activeKeyId) return null
  return UserApiKey.findOne({ userId, keyId: settings.activeKeyId }).lean()
}

async function attachUserImageApiKey(req, res, next) {
  try {
    const decoded = readJwt(req)
    if (!decoded) {
      logger.info(`user-image-api blocked: missing jwt cookie`)
      return res.status(401).json({ error: 'Unauthorized' })
    }
    if (decoded.role !== 'user' && decoded.role !== 'admin') return res.status(403).json({ error: 'Forbidden' })

    const activeKey = await getActiveUserKeyDoc(decoded)
    if (!activeKey?.apiKeyEnc) {
      logger.info(`user-image-api blocked: no active key for userId=${decoded.userId}`)
      return res.status(403).json({ error: 'No active API key' })
    }

    let apiKey
    try {
      apiKey = decryptString(activeKey.apiKeyEnc)
    } catch (e) {
      logger.error(`user-image-api decrypt failed userId=${decoded.userId}: ${e?.message || e}`)
      return res.status(500).json({ error: 'API key decrypt failed' })
    }

    req._userImageApiAuth = `Bearer ${String(apiKey).trim()}`
    next()
  } catch (err) {
    logger.error(`attachUserImageApiKey failed: ${err?.message || err}`)
    res.status(500).json({ error: 'Internal Server Error' })
  }
}

function isSafeState(s) {
  const v = String(s || '').trim()
  if (!v) return false
  if (v.length < 8 || v.length > 2048) return false
  return /^[A-Za-z0-9._:-]+$/.test(v) || v.split('.').length === 3
}

function decodeStateJwt(state) {
  try {
    const decoded = jwt.verify(String(state), JWT_SECRET)
    if (!decoded || typeof decoded !== 'object') return null
    const user_id = String(decoded.user_id || '').trim()
    const session_id = String(decoded.session_id || '').trim()
    if (!user_id || !session_id) return null
    return { user_id, session_id }
  } catch {
    return null
  }
}

function wowApiBase(region) {
  const r = String(region || 'eu').toLowerCase()
  return `https://${r}.api.blizzard.com`
}

async function exchangeBlizzardCodeForToken(code) {
  if (!BLIZZARD_CLIENT_ID || !BLIZZARD_CLIENT_SECRET) {
    throw new Error('BLIZZARD_CLIENT_ID/BLIZZARD_CLIENT_SECRET not set')
  }

  const body = new URLSearchParams()
  body.set('grant_type', 'authorization_code')
  body.set('code', String(code))
  body.set('redirect_uri', BLIZZARD_REDIRECT_URI)

  const basic = Buffer.from(`${BLIZZARD_CLIENT_ID}:${BLIZZARD_CLIENT_SECRET}`).toString('base64')

  const resp = await axios.post(
    BLIZZARD_TOKEN,
    body.toString(),
    {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${basic}`
      },
      timeout: 12000
    }
  )

  return resp.data || {}
}

function flattenWowCharacters(profileJson) {
  const out = []
  const accounts = Array.isArray(profileJson?.wow_accounts) ? profileJson.wow_accounts : []
  for (const acc of accounts) {
    const chars = Array.isArray(acc?.characters) ? acc.characters : []
    for (const c of chars) {
      const name = String(c?.name || '').trim()
      const realmName = String(c?.realm?.name || c?.realm?.slug || '').trim()
      if (!name || !realmName) continue
      out.push({ name, realm: realmName })
    }
  }
  const seen = new Set()
  const deduped = []
  for (const c of out) {
    const k = `${c.name}::${c.realm}`.toLowerCase()
    if (seen.has(k)) continue
    seen.add(k)
    deduped.push(c)
  }
  deduped.sort((a, b) => {
    const an = a.name.toLowerCase()
    const bn = b.name.toLowerCase()
    if (an < bn) return -1
    if (an > bn) return 1
    const ar = a.realm.toLowerCase()
    const br = b.realm.toLowerCase()
    if (ar < br) return -1
    if (ar > br) return 1
    return 0
  })
  return deduped
}

app.post('/oauth/state', async (req, res) => {
  try {
    const state = String(req.body?.state || '').trim()
    const user_id = String(req.body?.user_id || '').trim()
    const session_id = String(req.body?.session_id || '').trim()
    if (!isSafeState(state) || !user_id || !session_id) return res.status(400).json({ ok: false, error: 'invalid_request' })

    const ip = String(req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim()
    const ua = String(req.headers['user-agent'] || '').slice(0, 400)

    await Session.updateOne(
      { state },
      { $setOnInsert: { state, user_id, session_id, created_at: new Date() }, $set: { ip_address: ip, user_agent: ua } },
      { upsert: true }
    )

    res.json({ ok: true })
  } catch (err) {
    logger.error(`oauth/state failed: ${err?.message || err}`)
    res.status(500).json({ ok: false, error: 'server_error' })
  }
})

app.get('/oauth/login', async (req, res) => {
  try {
    const state = String(req.query?.state || '').trim()
    if (!isSafeState(state)) return res.status(400).send('Missing/invalid state')

    const q = new URLSearchParams()
    q.set('client_id', BLIZZARD_CLIENT_ID)
    q.set('scope', 'openid wow.profile')
    q.set('redirect_uri', BLIZZARD_REDIRECT_URI)
    q.set('response_type', 'code')
    q.set('state', state)

    res.redirect(302, `${BLIZZARD_AUTHORIZE}?${q.toString()}`)
  } catch (err) {
    logger.error(`oauth/login failed: ${err?.message || err}`)
    res.status(500).send('OAuth login error')
  }
})

app.get('/oauth/callback', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate')
  res.setHeader('Pragma', 'no-cache')
  res.setHeader('Expires', '0')
  res.sendFile(path.join(__dirname, 'public', 'callback.html'))
})

async function handleOAuthIntake(req, res) {
  const rid = crypto.randomBytes(8).toString('hex')
  try {
    const code = String((req.body?.code ?? req.query?.code) || '').trim()
    const state = String((req.body?.state ?? req.query?.state) || '').trim()
    if (!code || !isSafeState(state)) return res.status(400).json({ ok: false, error: 'Missing/invalid code/state', rid })

    let sess = await Session.findOne({ state }).lean()
    if (!sess) {
      const decoded = decodeStateJwt(state)
      if (!decoded) return res.status(400).json({ ok: false, error: 'Unknown state', rid })

      const ip = String(req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim()
      const ua = String(req.headers['user-agent'] || '').slice(0, 400)

      await Session.updateOne(
        { state },
        { $setOnInsert: { state, user_id: decoded.user_id, session_id: decoded.session_id, created_at: new Date() }, $set: { ip_address: ip, user_agent: ua } },
        { upsert: true }
      )

      sess = await Session.findOne({ state }).lean()
      if (!sess) return res.status(400).json({ ok: false, error: 'Unknown state', rid })
    }

    logger.info(`oauth/intake rid=${rid} exchanging code for token state=${state.slice(0, 12)}...`)

    const tokenData = await exchangeBlizzardCodeForToken(code)
    const accessToken = String(tokenData?.access_token || '').trim()
    const expiresIn = Number(tokenData?.expires_in || 0)
    if (!accessToken) return res.status(502).json({ ok: false, error: 'Token exchange failed', rid })

    const region = BLIZZARD_REGION || 'eu'
    const namespace = `profile-${region}`
    const url = `${wowApiBase(region)}/profile/user/wow`

    logger.info(`oauth/intake rid=${rid} fetching user profile url=${url} namespace=${namespace} locale=${WOW_LOCALE}`)

    const profileResp = await axios.get(url, {
      headers: { Authorization: `Bearer ${accessToken}` },
      params: { namespace, locale: WOW_LOCALE },
      timeout: 12000
    })

    const choices = flattenWowCharacters(profileResp.data || {})

    await Session.updateOne(
      { state },
      {
        $set: {
          oauth_access_token: accessToken,
          oauth_expires_at: expiresIn ? new Date(Date.now() + expiresIn * 1000) : null,
          oauth_region: region,
          oauth_locale: WOW_LOCALE,
          oauth_chars: choices,
          oauth_updated_at: new Date()
        }
      }
    )

    res.json({ ok: true, choices, rid })
  } catch (err) {
    const status = err?.response?.status || null
    const data = err?.response?.data ?? null
    const msg = String(err?.message || err || '')

    logger.error(`oauth/intake failed rid=${rid} msg=${msg} status=${status || ''} data=${typeof data === 'string' ? data : JSON.stringify(data || {})}`)

    res.status(500).json({
      ok: false,
      error: 'OAuth intake failed',
      rid,
      upstream_status: status,
      upstream_data: data,
      message: msg
    })
  }
}


app.get('/oauth/intake', handleOAuthIntake)
app.post('/oauth/intake', handleOAuthIntake)

async function oauthSubmitHandler(req, res) {
  try {
    const state = String((req.body?.state ?? req.query?.state) || '').trim()
    const choice = String((req.body?.choice ?? req.query?.choice) || '').trim()

    if (!isSafeState(state) || !choice.includes('::')) {
      return res.status(400).json({ ok: false, status: 'invalid_request' })
    }

    const sess = await Session.findOne({ state }).lean()
    if (!sess) return res.status(400).json({ ok: false, status: 'unknown_state' })

    const [nameRaw, realmRaw] = choice.split('::')
    const name = String(nameRaw || '').trim()
    const realm = String(realmRaw || '').trim()
    if (!name || !realm) return res.status(400).json({ ok: false, status: 'invalid_choice' })

    await Session.updateOne(
      { state },
      { $set: { oauth_selected_name: name, oauth_selected_realm: realm, oauth_selected_at: new Date() } }
    )

    res.json({ ok: true })
  } catch (err) {
    logger.error(`oauth/submit failed: ${err?.message || err}`)
    res.status(500).json({ ok: false, status: 'server_error' })
  }
}

app.post('/oauth/submit', oauthSubmitHandler)
app.get('/oauth/submit', oauthSubmitHandler)





app.get('/user/signup', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'user-signup.html')))
app.get('/user/auth', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'user-login.html')))

app.post('/user/register', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim()
    const password = String(req.body?.password || '')

    logger.info(`user/register attempt username="${username}"`)

    if (username.length < 3 || username.length > 32) return res.status(400).json({ error: 'Invalid username' })
    if (password.length < 8) return res.status(400).json({ error: 'Password too short' })

    const exists = await User.findOne({ username }).lean()
    if (exists) return res.status(409).json({ error: 'Username already taken' })

    const passwordHash = await bcrypt.hash(password, 12)
    const u = await User.create({ username, passwordHash })

    const token = signAuthToken({ role: 'user', userId: String(u._id), username: u.username })
    res.cookie('token', token, { httpOnly: false, secure: process.env.NODE_ENV === 'production', sameSite: 'Lax', path: '/', maxAge: 7 * 86400 * 1000 })
    res.json({ ok: true, redirect: '/image-host/' })
  } catch (err) {
    const code = err?.code
    const msg = String(err?.message || err || '')
    const keyPattern = err?.keyPattern || null
    const keyValue = err?.keyValue || null

    if (code === 11000 || msg.includes('E11000')) {
      const fields = keyPattern ? Object.keys(keyPattern) : (keyValue ? Object.keys(keyValue) : [])
      const field = fields[0] || 'unknown'

      logger.error(`user/register duplicate key field=${field} keyValue=${JSON.stringify(keyValue || {})}`)

      if (field === 'username') return res.status(409).json({ error: 'Username already taken' })
      return res.status(409).json({ error: `Conflict: duplicate ${field}` })
    }

    logger.error(`user/register failed: ${msg}`)
    res.status(500).json({ error: msg || 'Internal Server Error' })
  }
})

app.post('/user/login', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim()
    const password = String(req.body?.password || '')

    const u = await User.findOne({ username })
    if (!u) return res.status(401).json({ error: 'Invalid credentials' })

    const ok = await bcrypt.compare(password, u.passwordHash)
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' })

    const token = signAuthToken({ role: 'user', userId: String(u._id), username: u.username })
    res.cookie('token', token, { httpOnly: false, secure: process.env.NODE_ENV === 'production', sameSite: 'Lax', path: '/', maxAge: 7 * 86400 * 1000 })
    res.json({ ok: true, redirect: '/image-host/' })
  } catch (err) {
    logger.error(`user/login failed: ${err?.message || err}`)
    res.status(500).json({ error: 'Internal Server Error' })
  }
})

app.post('/user/logout', (_req, res) => {
  res.cookie('token', '', { httpOnly: false, secure: process.env.NODE_ENV === 'production', sameSite: 'Lax', path: '/', expires: new Date(0) })
  res.json({ ok: true })
})

app.options('/image-api/*', (_req, res) => res.sendStatus(204))
app.options('/user-image-api/*', (_req, res) => res.sendStatus(204))

const publicImageProxy = createProxyMiddleware({
  target: IMAGE_API_TARGET,
  changeOrigin: true,
  secure: true,
  xfwd: true,
  proxyTimeout: 60000,
  timeout: 60000,
  pathRewrite: { '^/img': '' }
})

app.use('/img', publicImageProxy)

function firstForwarded(v) {
  return String(v || '').split(',')[0].trim()
}

function makePublicImgBase(req) {
  const proto = firstForwarded(req.headers['x-forwarded-proto']) || req.protocol || 'https'
  const host = firstForwarded(req.headers['x-forwarded-host']) || String(req.headers.host || '')
  return `${proto}://${host}`.replace(/\/$/, '') + '/img'
}

function rewriteImageLinksInJson(req, bodyBuffer) {
  try {
    const txt = bodyBuffer.toString('utf8')
    const data = JSON.parse(txt)

    if (!data || typeof data !== 'object') return bodyBuffer

    if (data.direct_url || data.page_url) {
      const base = makePublicImgBase(req)

      if (typeof data.direct_url === 'string') {
        data.direct_url = data.direct_url
          .replace(/^https?:\/\/[^/]+\/image-api\b/i, base)
          .replace(/^https?:\/\/[^/]+\/user-image-api\b/i, base)
          .replace(/^https?:\/\/[^/]+\/img\b/i, base)
          .replace(/^https?:\/\/[^/]+$/i, base.replace(/\/img$/, ''))
          .replace(/\/i\//i, '/i/')
          .replace(/\/v\//i, '/v/')

        if (/\/image-api\/i\//i.test(data.direct_url)) data.direct_url = data.direct_url.replace(/\/image-api\b/i, '')
        if (/\/user-image-api\/i\//i.test(data.direct_url)) data.direct_url = data.direct_url.replace(/\/user-image-api\b/i, '')
      }

      if (typeof data.page_url === 'string') {
        data.page_url = data.page_url
          .replace(/^https?:\/\/[^/]+\/image-api\b/i, base)
          .replace(/^https?:\/\/[^/]+\/user-image-api\b/i, base)
          .replace(/^https?:\/\/[^/]+\/img\b/i, base)
          .replace(/^https?:\/\/[^/]+$/i, base.replace(/\/img$/, ''))
          .replace(/\/i\//i, '/i/')
          .replace(/\/v\//i, '/v/')

        if (/\/image-api\/v\//i.test(data.page_url)) data.page_url = data.page_url.replace(/\/image-api\b/i, '')
        if (/\/user-image-api\/v\//i.test(data.page_url)) data.page_url = data.page_url.replace(/\/user-image-api\b/i, '')
      }

      return Buffer.from(JSON.stringify(data))
    }

    return bodyBuffer
  } catch {
    return bodyBuffer
  }
}

app.use('/sharex', createProxyMiddleware({
  target: IMAGE_API_TARGET,
  changeOrigin: true,
  secure: true,
  xfwd: true,
  proxyTimeout: 60000,
  timeout: 60000,
  pathRewrite: { '^/sharex': '' },
  onProxyReq: (proxyReq, req) => {
    const auth = req.headers.authorization || req.headers.Authorization
    if (auth) proxyReq.setHeader('Authorization', auth)
  },
  onError: (_err, _req, res) => {
    res.status(502).json({ error: 'ShareX proxy error' })
  }
}))

const imageApiProxy = createProxyMiddleware({
  target: IMAGE_API_TARGET,
  changeOrigin: true,
  secure: true,
  xfwd: true,
  proxyTimeout: 60000,
  timeout: 60000,
  selfHandleResponse: true,
  pathRewrite: { '^/image-api': '' },
  onProxyReq: (proxyReq) => {
    if (!IMAGE_API_KEY) throw new Error('IMAGE_API_KEY is not set on Node server')
    proxyReq.setHeader('Authorization', `Bearer ${String(IMAGE_API_KEY).trim()}`)
  },
  onProxyRes: responseInterceptor(async (responseBuffer, proxyRes, req, res) => {
    const ct = String(proxyRes.headers['content-type'] || '')
    if (ct.includes('application/json')) {
      return rewriteImageLinksInJson(req, responseBuffer)
    }
    return responseBuffer
  }),
  onError: (_err, _req, res) => {
    res.status(502).json({ error: 'Image API proxy error' })
  }
})

app.use('/image-api', verifyTokenApi, requireAdminApi, imageApiProxy)

const userImageApiProxy = createProxyMiddleware({
  target: IMAGE_API_TARGET,
  changeOrigin: true,
  secure: true,
  xfwd: true,
  proxyTimeout: 60000,
  timeout: 60000,
  pathRewrite: (path, req) => {
    const p = String(path || "")
    if (p.startsWith("/user-image-api")) return p.replace("/user-image-api", "")
    return p
  },
  onProxyReq: (proxyReq, req) => {
    const auth = req._userImageApiAuth
    if (!auth) return
    const key = String(auth).replace(/^Bearer\s+/i, "").trim()
    proxyReq.setHeader("Authorization", `Bearer ${key}`)

    const orig = req.originalUrl || req.url || ""
    logger.info(`user-image-api proxyReq: orig=${orig} -> ${proxyReq.path}`)
  },
  onProxyRes: (proxyRes, req) => {
    const p = req.originalUrl || req.url || ""
    logger.info(`user-image-api upstream status=${proxyRes.statusCode} path=${p}`)
  },
  onError: (_err, req, res) => {
    const p = req.originalUrl || req.url || ""
    logger.error(`user-image-api proxy error path=${p}`)
    res.status(502).json({ error: "User image proxy error" })
  }
})

app.use("/user-image-api", verifyTokenApi, requireUserApi, attachUserImageApiKey, userImageApiProxy)

app.get('/api/user/me', verifyTokenApi, requireUserApi, (req, res) => {
  res.json({ userId: req.auth.userId, username: req.auth.username, role: req.auth.role })
})

const weatherLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false
})

const weatherCache = new Map()
function weatherCacheKey(city) {
  return String(city || '').trim().toLowerCase()
}
function pickCity(q) {
  const city = String(q || '').trim()
  if (!city) return ''
  if (city.length > 80) return city.slice(0, 80)
  return city
}

app.get('/api/weather', weatherLimiter, async (req, res) => {
  try {
    if (!OPENWEATHER_API_KEY) return res.status(500).json({ error: 'OPENWEATHER_API_KEY is not set' })

    const city = pickCity(req.query?.city)
    if (!city) return res.status(400).json({ error: 'Missing city' })

    const key = weatherCacheKey(city)
    const now = Date.now()
    const cached = weatherCache.get(key)
    if (cached && cached.expiresAt > now) return res.json(cached.payload)

    const url = 'https://api.openweathermap.org/data/2.5/weather'
    const resp = await axios.get(url, {
      params: {
        q: city,
        appid: OPENWEATHER_API_KEY,
        units: 'metric'
      },
      timeout: 8000
    })

    const w = resp.data || {}
    const main = w.main || {}
    const wind = w.wind || {}
    const weatherArr = Array.isArray(w.weather) ? w.weather : []
    const first = weatherArr[0] || {}

    const payload = {
      ok: true,
      city: String(w.name || city),
      condition: String(first.description || first.main || 'Unknown'),
      conditionIcon: String(first.icon || '01d'),
      temperature: typeof main.temp === 'number' ? main.temp : null,
      humidity: typeof main.humidity === 'number' ? main.humidity : null,
      wind_speed: typeof wind.speed === 'number' ? wind.speed : null
    }

    weatherCache.set(key, { expiresAt: now + 10 * 60 * 1000, payload })
    res.json(payload)
  } catch (err) {
    const status = err?.response?.status
    const msg = err?.response?.data?.message || err?.message || 'Weather request failed'
    if (status === 404) return res.status(404).json({ error: 'City not found' })
    res.status(502).json({ error: String(msg) })
  }
})

app.get('/api/user/keys', verifyTokenApi, requireUserApi, async (req, res) => {
  try {
    const userId = new mongoose.Types.ObjectId(String(req.auth.userId))
    const keys = await UserApiKey.find({ userId }).sort({ createdAt: -1 }).limit(25).lean()
    const settings = await UserSettings.findOne({ userId }).lean()
    const activeKeyId = settings?.activeKeyId || ''
    const active = activeKeyId ? keys.find(k => k.keyId === activeKeyId) : null
    const activeApiKey = active?.apiKeyEnc ? decryptString(active.apiKeyEnc) : ''

    res.json({
      ok: true,
      imageHost: IMAGE_HOST_ADMIN_TARGET.replace(/\/$/, ''),
      activeKeyId,
      activeApiKey,
      keys: keys.map(k => ({
        keyId: k.keyId,
        name: k.name,
        scopes: k.scopes,
        ratePerMinute: k.ratePerMinute,
        createdAt: k.createdAt
      }))
    })
  } catch (err) {
    res.status(500).json({ error: String(err?.message || err) })
  }
})

app.get('/api/user/profile', verifyTokenApi, requireUserApi, async (req, res) => {
  try {
    const userId = new mongoose.Types.ObjectId(String(req.auth.userId))
    const u = await User.findById(userId).lean()
    if (!u) return res.status(404).json({ error: 'User not found' })

    const s = await UserSettings.findOne({ userId }).lean()

    res.json({
      ok: true,
      user: {
        userId: String(userId),
        username: u.username,
        avatarDirectUrl: s?.avatarDirectUrl || '',
        avatarPageUrl: s?.avatarPageUrl || ''
      }
    })
  } catch (err) {
    res.status(500).json({ error: String(err?.message || err) })
  }
})

app.post('/api/user/profile/username', verifyTokenApi, requireUserApi, async (req, res) => {
  try {
    const userId = new mongoose.Types.ObjectId(String(req.auth.userId))
    const nextUsername = String(req.body?.username || '').trim()

    if (nextUsername.length < 3 || nextUsername.length > 32) {
      return res.status(400).json({ error: 'Username must be 3–32 characters' })
    }

    const exists = await User.findOne({ username: nextUsername }).lean()
    if (exists && String(exists._id) !== String(userId)) {
      return res.status(409).json({ error: 'Username already taken' })
    }

    const updated = await User.findByIdAndUpdate(
      userId,
      { $set: { username: nextUsername } },
      { new: true }
    ).lean()

    if (!updated) return res.status(404).json({ error: 'User not found' })

    const token = signAuthToken({ role: req.auth.role, userId: String(userId), username: nextUsername })
    res.cookie('token', token, { httpOnly: false, secure: process.env.NODE_ENV === 'production', sameSite: 'Lax', path: '/', maxAge: 7 * 86400 * 1000 })

    res.json({ ok: true, username: nextUsername })
  } catch (err) {
    res.status(500).json({ error: String(err?.message || err) })
  }
})

app.post('/api/user/profile/password', verifyTokenApi, requireUserApi, async (req, res) => {
  try {
    const userId = new mongoose.Types.ObjectId(String(req.auth.userId))
    const currentPassword = String(req.body?.currentPassword || '')
    const newPassword = String(req.body?.newPassword || '')

    if (newPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' })

    const u = await User.findById(userId)
    if (!u) return res.status(404).json({ error: 'User not found' })

    const ok = await bcrypt.compare(currentPassword, u.passwordHash)
    if (!ok) return res.status(401).json({ error: 'Current password is incorrect' })

    const passwordHash = await bcrypt.hash(newPassword, 12)
    await User.updateOne({ _id: userId }, { $set: { passwordHash } })

    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: String(err?.message || err) })
  }
})

app.post('/api/user/profile/avatar', verifyTokenApi, requireUserApi, async (req, res) => {
  try {
    const userId = new mongoose.Types.ObjectId(String(req.auth.userId))
    const avatarDirectUrl = String(req.body?.avatarDirectUrl || '').trim()
    const avatarPageUrl = String(req.body?.avatarPageUrl || '').trim()

    if (!avatarDirectUrl) return res.status(400).json({ error: 'Missing avatarDirectUrl' })
    if (!/^https?:\/\//i.test(avatarDirectUrl) && !avatarDirectUrl.startsWith('/')) {
      return res.status(400).json({ error: 'Invalid avatarDirectUrl' })
    }

    await UserSettings.updateOne(
      { userId },
      { $setOnInsert: { userId }, $set: { avatarDirectUrl, avatarPageUrl, updatedAt: new Date() } },
      { upsert: true }
    )

    res.json({ ok: true, avatarDirectUrl, avatarPageUrl })
  } catch (err) {
    res.status(500).json({ error: String(err?.message || err) })
  }
})

app.post('/api/user/profile/avatar/remove', verifyTokenApi, requireUserApi, async (req, res) => {
  try {
    const userId = new mongoose.Types.ObjectId(String(req.auth.userId))

    await UserSettings.updateOne(
      { userId },
      { $setOnInsert: { userId }, $set: { avatarDirectUrl: '', avatarPageUrl: '', updatedAt: new Date() } },
      { upsert: true }
    )

    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: String(err?.message || err) })
  }
})

app.post('/api/user/keys/create', verifyTokenApi, requireUserApi, async (req, res) => {
  try {
    if (!IMAGE_HOST_ADMIN_TARGET) return res.status(500).json({ error: 'IMAGE_HOST_ADMIN_TARGET not set' })
    if (!IMAGE_HOST_ADMIN_SECRET) return res.status(500).json({ error: 'IMAGE_HOST_ADMIN_SECRET not set' })

    const target = IMAGE_HOST_ADMIN_TARGET.replace(/\/$/, '')
    const name = String(req.body?.name || req.auth.username || 'user').slice(0, 64)

    const body = new URLSearchParams()
    body.set('name', name)
    body.set('scopes', 'upload,fetch')
    body.set('rate_per_minute', '30')
    body.set('never_expires', '1')
    body.set('user_id', String(req.auth.userId))

    const resp = await axios.post(
      `${target}/admin/keys/rotate`,
      body.toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'x-admin-secret': String(IMAGE_HOST_ADMIN_SECRET).trim() }, timeout: 12000 }
    )

    const keyId = String(resp.data?.key_id || '')
    const apiKey = String(resp.data?.api_key || '')
    if (!keyId || !apiKey) return res.status(502).json({ error: 'Upstream did not return key_id/api_key' })

    const userId = new mongoose.Types.ObjectId(String(req.auth.userId))
    const apiKeyEnc = encryptString(apiKey)
    const keyHash = sha256Hex(apiKey)

    await UserApiKey.deleteMany({ userId })

    await UserApiKey.updateOne(
      { userId, keyId },
      { $set: { apiKeyEnc, keyHash, name, scopes: ['upload', 'fetch'], ratePerMinute: 30 } },
      { upsert: true }
    )

    await UserSettings.updateOne(
      { userId },
      { $setOnInsert: { userId }, $set: { activeKeyId: keyId, updatedAt: new Date() } },
      { upsert: true }
    )

    res.json({ ok: true, keyId, apiKey })
  } catch (err) {
    res.status(err?.response?.status || 500).json({ error: err?.response?.data || String(err?.message || err) })
  }
})

app.post('/api/user/keys/activate', verifyTokenApi, requireUserApi, async (req, res) => {
  try {
    const keyId = String(req.body?.keyId || '').trim()
    if (!keyId) return res.status(400).json({ error: 'Missing keyId' })

    const userId = new mongoose.Types.ObjectId(String(req.auth.userId))
    const exists = await UserApiKey.findOne({ userId, keyId }).lean()
    if (!exists) return res.status(404).json({ error: 'Key not found' })

    await UserSettings.updateOne(
      { userId },
      { $setOnInsert: { userId }, $set: { activeKeyId: keyId, updatedAt: new Date() } },
      { upsert: true }
    )

    res.json({ ok: true, activeKeyId: keyId })
  } catch (err) {
    res.status(500).json({ error: String(err?.message || err) })
  }
})

app.get('/image-host/', verifyTokenPage('/user/auth'), requireUserPage, (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate')
  res.setHeader('Pragma', 'no-cache')
  res.setHeader('Expires', '0')
  res.sendFile(path.join(__dirname, 'public', 'image-host', 'dashboard.html'))
})

app.get('/image-host/upload', verifyTokenPage('/user/auth'), requireUserPage, (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate')
  res.setHeader('Pragma', 'no-cache')
  res.setHeader('Expires', '0')
  res.sendFile(path.join(__dirname, 'public', 'image-host', 'upload.html'))
})

app.get('/image-host/fetch', verifyTokenPage('/user/auth'), requireUserPage, (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate')
  res.setHeader('Pragma', 'no-cache')
  res.setHeader('Expires', '0')
  res.sendFile(path.join(__dirname, 'public', 'image-host', 'fetch.html'))
})

app.get('/image-host/profile', verifyTokenPage('/user/auth'), requireUserPage, (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate')
  res.setHeader('Pragma', 'no-cache')
  res.setHeader('Expires', '0')
  res.sendFile(path.join(__dirname, 'public', 'image-host', 'profile.html'))
})

app.get('/auth', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'admin-login.html')))

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: 'Too many login attempts from this IP, please try again after 15 minutes' })

app.post('/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body || {}
    const adminUsername = process.env.ADMIN_USERNAME || ''
    const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH || ''
    if (!adminUsername || !adminPasswordHash) return res.status(500).json({ auth: false, message: 'Admin not configured' })

    if (String(username || '') !== adminUsername) return res.status(401).json({ auth: false, message: 'Invalid username or password' })
    const isPasswordValid = await bcrypt.compare(String(password || ''), adminPasswordHash)
    if (!isPasswordValid) return res.status(401).json({ auth: false, message: 'Invalid username or password' })

    const token = signAuthToken({ role: 'admin', adminId: adminUsername, username: adminUsername })
    res.cookie('token', token, { httpOnly: false, secure: process.env.NODE_ENV === 'production', sameSite: 'Lax', path: '/', maxAge: 7 * 86400 * 1000 })

    req.session.save((err) => {
      if (err) return res.status(500).json({ auth: false, message: 'Error saving session' })
      res.status(200).json({ auth: true, redirect: '/admin' })
    })
  } catch {
    res.status(500).json({ auth: false, message: 'Internal Server Error' })
  }
})

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('admin_session_cookie', { path: '/', httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict' })
    res.cookie('token', '', { httpOnly: false, secure: process.env.NODE_ENV === 'production', sameSite: 'Lax', path: '/', expires: new Date(0) })
    res.redirect('/auth')
  })
})

app.get('/admin', verifyTokenPage('/auth'), requireAdminPage, (_req, res) => res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html')))
app.get('/admin-dashboard.html', (_req, res) => res.redirect('/admin'))

app.use(express.static(path.join(__dirname, 'public'), { etag: false, maxAge: 0, lastModified: false, redirect: false }))

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
const sessions = {}
const openAICallLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, message: { error: 'Too many requests, please try again later.' }, standardHeaders: true, legacyHeaders: false })

async function makeOpenAIRequest(messages, retries = 3, backoff = 1000) {
  try {
    const response = await openai.chat.completions.create({
      model: 'gpt-3.5-turbo',
      messages,
      temperature: 0.7,
      max_tokens: 150
    })
    const out = response?.choices?.[0]?.message?.content
    return String(out || '').trim()
  } catch (error) {
    const status = error?.status || error?.response?.status
    if (status === 429 && retries > 0) {
      await new Promise(r => setTimeout(r, backoff))
      return makeOpenAIRequest(messages, retries - 1, backoff * 2)
    }
    throw error
  }
}

app.post('/api/openai-chat', openAICallLimiter, async (req, res) => {
  const { message, sessionId } = req.body || {}
  if (!message || !sessionId) return res.status(400).json({ error: 'Message and sessionId are required.' })
  if (!sessions[sessionId]) sessions[sessionId] = [{ role: 'system', content: 'You are Haru AI, a helpful assistant.' }]
  sessions[sessionId].push({ role: 'user', content: String(message) })
  try {
    const botResponse = await makeOpenAIRequest(sessions[sessionId])
    sessions[sessionId].push({ role: 'assistant', content: botResponse })
    res.json({ response: botResponse })
  } catch (error) {
    const status = error?.status || error?.response?.status
    if (status === 429) res.status(429).json({ error: 'Too many requests. Please try again later.' })
    else res.status(500).json({ error: 'An error occurred while processing your request.' })
  }
})

const HEARTBEAT_TIMEOUT = 60000
const videoHeartbeat = {}
let currentVideo = null
let currentBrowsing = null

function emitCurrentPresence(socket) {
  if (currentVideo) socket.emit('presenceUpdate', { presenceType: 'video', ...currentVideo })
  else if (currentBrowsing) socket.emit('presenceUpdate', { presenceType: 'browsing', ...currentBrowsing })
  else socket.emit('presenceUpdate', { presenceType: 'offline' })
}

function handleBrowsingPresence(data) {
  currentVideo = null
  currentBrowsing = {
    title: data.title || 'YouTube',
    description: data.description || 'Browsing videos',
    thumbnail: data.thumbnail || 'https://www.youtube.com/img/desktop/yt_1200.png',
    timeElapsed: Number(data.timeElapsed || 0)
  }
}

function handleVideoPresence(data) {
  const presence = {
    videoId: data.videoId,
    title: data.title,
    description: data.description,
    channelTitle: data.channelTitle,
    viewCount: data.viewCount,
    likeCount: data.likeCount,
    publishedAt: data.publishedAt,
    category: data.category,
    thumbnail: data.thumbnail,
    currentTime: data.currentTime,
    duration: data.duration,
    isPaused: data.isPaused,
    isLive: data.isLive
  }
  if (currentVideo?.videoId === data.videoId) Object.assign(currentVideo, presence)
  else {
    currentVideo = presence
    currentBrowsing = null
  }
}

function handleOfflinePresence() {
  currentVideo = null
  currentBrowsing = null
}

setInterval(() => {
  const now = Date.now()
  for (const [videoId, ts] of Object.entries(videoHeartbeat)) {
    if (now - ts > HEARTBEAT_TIMEOUT) {
      delete videoHeartbeat[videoId]
      handleOfflinePresence()
      io.emit('presenceUpdate', { presenceType: 'offline' })
      break
    }
  }
}, Math.floor(HEARTBEAT_TIMEOUT / 2))

io.on('connection', (socket) => {
  emitCurrentPresence(socket)

  socket.on('presenceUpdate', (data) => {
    const p = String(data?.presenceType || '')
    if (p === 'video') handleVideoPresence(data || {})
    else if (p === 'browsing') handleBrowsingPresence(data || {})
    else handleOfflinePresence()
    socket.broadcast.emit('presenceUpdate', data)
  })

  socket.on('updateBrowsingPresence', (data) => {
    handleBrowsingPresence(data || {})
    socket.broadcast.emit('presenceUpdate', { presenceType: 'browsing', ...currentBrowsing })
  })

  socket.on('updateVideoProgress', (data) => {
    handleVideoPresence(data || {})
    socket.broadcast.emit('presenceUpdate', { presenceType: 'video', ...currentVideo })
  })

  socket.on('heartbeat', (data, ack) => {
    const videoId = String(data?.videoId || '')
    if (currentVideo?.videoId && videoId && currentVideo.videoId === videoId) {
      videoHeartbeat[videoId] = Date.now()
      if (ack) ack({ status: 'ok' })
    } else {
      if (ack) ack({ status: 'error', message: 'Unknown video ID' })
    }
  })
})

server.listen(PORT, () => { logger.info(`Server is running on port ${PORT}`) })
