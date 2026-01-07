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
const { DateTime } = require('luxon')
const { body, validationResult } = require('express-validator')
const cors = require('cors')
const rateLimit = require('express-rate-limit')
const OpenAI = require('openai')
const { MongoClient } = require('mongodb')
const nacl = require('tweetnacl')
const os = require('os')
const crypto = require('crypto')
const { createProxyMiddleware } = require('http-proxy-middleware')

dotenv.config()

const DISCORD_PUBLIC_KEY = process.env.DISCORD_PUBLIC_KEY || ''
const OPENWEATHER_API_KEY = process.env.OPENWEATHER_API_KEY || ''
const BOT_TOKEN = process.env.BOT_TOKEN || ''
const PORT = process.env.PORT || 3000

const IMAGE_API_TARGET = (process.env.IMAGE_API_TARGET || 'https://image-host-bde701503cb6.herokuapp.com').trim()
const IMAGE_API_KEY = (process.env.IMAGE_API_KEY || '').trim()

const IMAGE_HOST_ADMIN_TARGET = (process.env.IMAGE_HOST_ADMIN_TARGET || '').trim()
const IMAGE_HOST_ADMIN_SECRET = (process.env.IMAGE_HOST_ADMIN_SECRET || '').trim()

const ORIGIN = process.env.PROXY_ORIGIN || 'http://us-nyc-02.wisp.uno:8282'

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
      'blob:',
      'data:',
      'https://i.ytimg.com',
      'https://img.youtube.com',
      'https://ytimg.com',
      'https://openweathermap.org',
      'https://i.postimg.cc',
      'https://threejs.org',
      'https://www.youtube.com',
      'https://www.youtube-nocookie.com',
      'https://raw.githubusercontent.com',
      'https://api.tiles.mapbox.com',
      'https://*.tiles.mapbox.com',
      'https://raider.io',
      'https://render.worldofwarcraft.com',
      'https://images.mikumiku.dev'
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
  apiKey: { type: String, required: true },
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

const sessionStore = MongoStore.create({
  mongoUrl,
  collectionName: 'sessions',
  ttl: 14 * 24 * 60 * 60,
  autoRemove: 'native'
})

sessionStore.on('connected', () => { logger.info('Session store connected to MongoDB') })
sessionStore.on('error', (error) => { logger.error(`Session store error: ${error}`) })

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

async function getActiveUserKey(userId) {
  const settings = await UserSettings.findOne({ userId }).lean()
  if (!settings?.activeKeyId) return null
  return UserApiKey.findOne({ userId, keyId: settings.activeKeyId }).lean()
}

app.get('/user/signup', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'user-signup.html')))
app.get('/user/auth', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'user-login.html')))

app.post('/user/register', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim()
    const password = String(req.body?.password || '')

    if (username.length < 3 || username.length > 32) return res.status(400).json({ error: 'Invalid username' })
    if (password.length < 8) return res.status(400).json({ error: 'Password too short' })

    const exists = await User.findOne({ username })
    if (exists) return res.status(409).json({ error: 'Username already taken' })

    const passwordHash = await bcrypt.hash(password, 12)
    const u = await User.create({ username, passwordHash })

    const token = signAuthToken({ role: 'user', userId: String(u._id), username: u.username })
    res.cookie('token', token, { httpOnly: false, secure: process.env.NODE_ENV === 'production', sameSite: 'Lax', path: '/', maxAge: 7 * 86400 * 1000 })
    res.json({ ok: true, redirect: '/image-host/' })
  } catch (err) {
    logger.error(`user/register failed: ${err?.message || err}`)
    res.status(500).json({ error: 'Internal Server Error' })
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

const IPINFO_API_KEY = process.env.IPINFO_API_KEY
if (!IPINFO_API_KEY) {
  logger.error('IPINFO_API_KEY environment variable is not set.')
  process.exit(1)
}

const getClientIp = (req) => {
  const forwardedFor = req.headers['x-forwarded-for']
  if (forwardedFor) return String(forwardedFor).split(',')[0].trim()
  return req.connection.remoteAddress
}

async function getGeoLocation(ip) {
  try {
    const ipInfoResponse = await axios.get(`https://ipinfo.io/${ip}/json?token=${IPINFO_API_KEY}`)
    const ipInfoData = ipInfoResponse.data
    return {
      city: ipInfoData.city || 'Unknown',
      region: ipInfoData.region || 'Unknown',
      country: ipInfoData.country || 'Unknown',
      ip,
      loc: ipInfoData.loc || null
    }
  } catch {
    return { city: 'Unknown', region: 'Unknown', country: 'Unknown', ip, loc: null }
  }
}

app.options('/image-api/*', (_req, res) => res.sendStatus(204))
app.options('/user-image-api/*', (_req, res) => res.sendStatus(204))

const imageApiProxy = createProxyMiddleware({
  target: IMAGE_API_TARGET,
  changeOrigin: true,
  secure: true,
  xfwd: true,
  proxyTimeout: 60000,
  timeout: 60000,
  pathRewrite: { '^/image-api': '' },
  onProxyReq: (proxyReq) => {
    if (!IMAGE_API_KEY) throw new Error('IMAGE_API_KEY is not set on Node server')
    proxyReq.setHeader('Authorization', `Bearer ${String(IMAGE_API_KEY).trim()}`)
  },
  onError: (_err, _req, res) => {
    res.status(502).json({ detail: 'Image API proxy error' })
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
  pathRewrite: { '^/user-image-api': '' },
  onProxyReq: async (proxyReq, req) => {
    const decoded = readJwt(req)
    if (!decoded || (decoded.role !== 'user' && decoded.role !== 'admin')) throw new Error('Forbidden')

    const userId = new mongoose.Types.ObjectId(String(decoded.userId))
    const activeKey = await getActiveUserKey(userId)
    if (!activeKey?.apiKeyEnc) throw new Error('No active API key')

    const apiKey = decryptString(activeKey.apiKeyEnc)
    proxyReq.setHeader('Authorization', `Bearer ${String(apiKey).trim()}`)
  },
  onError: (_err, _req, res) => {
    res.status(502).json({ error: 'User image proxy error' })
  }
})
app.use('/user-image-api', verifyTokenApi, requireUserApi, userImageApiProxy)

app.get('/api/user/me', verifyTokenApi, requireUserApi, (req, res) => {
  res.json({ userId: req.auth.userId, username: req.auth.username, role: req.auth.role })
})

app.get('/api/user/keys', verifyTokenApi, requireUserApi, async (req, res) => {
  try {
    const userId = new mongoose.Types.ObjectId(String(req.auth.userId))
    const keys = await UserApiKey.find({ userId }).sort({ createdAt: -1 }).limit(25).lean()
    const settings = await UserSettings.findOne({ userId }).lean()
    const activeKeyId = settings?.activeKeyId || ''
    const active = activeKeyId ? keys.find(k => k.keyId === activeKeyId) : null

    res.json({
      imageHost: IMAGE_HOST_ADMIN_TARGET.replace(/\/$/, ''),
      activeKeyId,
      activeApiKey: active?.apiKey || '',
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
      `${target}/admin/keys/create`,
      body.toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'x-admin-secret': String(IMAGE_HOST_ADMIN_SECRET).trim() } }
    )

    const keyId = String(resp.data?.key_id || '')
    const apiKey = String(resp.data?.api_key || '')
    if (!keyId || !apiKey) return res.status(500).json({ error: 'Upstream did not return key_id/api_key' })

    const userId = new mongoose.Types.ObjectId(String(req.auth.userId))
    const keyHash = sha256Hex(apiKey)

    await UserApiKey.updateOne(
      { userId, keyId },
      { $set: { apiKey, keyHash, name, scopes: ['upload', 'fetch'], ratePerMinute: 30 } },
      { upsert: true }
    )

    await UserSettings.updateOne(
      { userId },
      { $setOnInsert: { userId }, $set: { activeKeyId: keyId, updatedAt: new Date() } },
      { upsert: true }
    )

    res.json({ ok: true, imageHost: target, keyId, apiKey })
  } catch (err) {
    res.status(err?.response?.status || 500).json({ error: err?.response?.data || String(err?.message || err) })
  }
})

app.post('/api/user/keys/activate', verifyTokenApi, requireUserApi, async (req, res) => {
  try {
    const keyId = String(req.body?.keyId || '').trim()
    if (!keyId) return res.status(400).json({ error: 'Missing keyId' })

    const userId = new mongoose.Types.ObjectId(String(req.auth.userId))
    const exists = await UserApiKey.findOne({ userId, keyId })
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

app.post('/api/image-host/keys/create', verifyTokenApi, requireAdminApi, async (req, res) => {
  try {
    if (!IMAGE_HOST_ADMIN_TARGET) return res.status(500).json({ error: 'IMAGE_HOST_ADMIN_TARGET not set' })
    if (!IMAGE_HOST_ADMIN_SECRET) return res.status(500).json({ error: 'IMAGE_HOST_ADMIN_SECRET not set' })

    const target = IMAGE_HOST_ADMIN_TARGET.replace(/\/$/, '')
    const name = String(req.body?.name || 'user').slice(0, 64)
    const scopes = String(req.body?.scopes || 'upload,fetch')
    const rpm = Number.isFinite(Number(req.body?.rate_per_minute)) ? String(parseInt(req.body.rate_per_minute, 10)) : '30'

    const bodyParams = new URLSearchParams()
    bodyParams.set('name', name)
    bodyParams.set('scopes', scopes)
    bodyParams.set('rate_per_minute', rpm)
    bodyParams.set('never_expires', '1')

    const resp = await axios.post(
      `${target}/admin/keys/create`,
      bodyParams.toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'x-admin-secret': String(IMAGE_HOST_ADMIN_SECRET).trim() } }
    )

    res.json({ ...resp.data, image_host: target })
  } catch (err) {
    res.status(err?.response?.status || 500).json({ error: err?.response?.data || err?.message || 'Failed' })
  }
})

app.get('/image-host/', verifyTokenPage('/user/auth'), requireUserPage, (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate')
  res.setHeader('Pragma', 'no-cache')
  res.setHeader('Expires', '0')
  res.sendFile(path.join(__dirname, 'public', 'image-host', 'index.html'))
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

app.get('/api/geo-data', verifyTokenApi, requireAdminApi, async (_req, res) => {
  try {
    const byCountry = await GeoData.aggregate([{ $group: { _id: '$country', count: { $sum: 1 } } }, { $sort: { count: -1 } }])
    res.json(byCountry)
  } catch {
    res.status(500).json({ error: 'Failed to fetch geo data' })
  }
})

const blockedIps = new Set()

app.post('/api/block-user', verifyTokenApi, requireAdminApi, (req, res) => {
  const ip = String(req.body?.ip || '').trim()
  if (!ip) return res.status(400).json({ status: 'error', message: 'Missing ip' })
  blockedIps.add(ip)
  for (const [, s] of io.of('/').sockets) {
    const sip = s.handshake.headers['x-forwarded-for']?.split(',')[0].trim() || s.handshake.address
    if (sip === ip) s.disconnect(true)
  }
  res.json({ status: 'success' })
})

app.post('/api/unblock-user', verifyTokenApi, requireAdminApi, (req, res) => {
  const ip = String(req.body?.ip || '').trim()
  if (!ip) return res.status(400).json({ status: 'error', message: 'Missing ip' })
  blockedIps.delete(ip)
  res.json({ status: 'success' })
})

app.post('/track-visitor', async (req, res) => {
  const ip = getClientIp(req)
  try {
    const loc = await getGeoLocation(ip)
    const city = loc.city || 'Unknown'
    const region = loc.region || 'Unknown'
    const country = loc.country || 'Unknown'
    await GeoData.updateOne(
      { ip },
      { $set: { city, region, country }, $setOnInsert: { timestamp: new Date() } },
      { upsert: true }
    )
    const byCountry = await GeoData.aggregate([{ $group: { _id: '$country', count: { $sum: 1 } } }, { $sort: { count: -1 } }])
    io.emit('geoDataUpdate', byCountry)

    if (loc && loc.loc) {
      const [latitude, longitude] = loc.loc.split(',')
      io.emit('visitorLocation', { id: ip, latitude: parseFloat(latitude), longitude: parseFloat(longitude), info: `${city}, ${country}` })
    }

    res.status(200).json({ success: true })
  } catch (err) {
    logger.error(`track-visitor failed for ${ip}: ${err?.message || 'error'}`)
    res.status(500).json({ success: false })
  }
})

const dbName = process.env.MONGO_DB_NAME || 'myfirstdatabase'
const client = new MongoClient(process.env.MONGO_URL, {})
let timelineCollection
let configCollection

async function connectToMongo() {
  try {
    await client.connect()
    const db2 = client.db(dbName)
    configCollection = db2.collection('config')
    timelineCollection = db2.collection('timeline')
    const toggleDoc = await configCollection.findOne({ _id: 'toggle' })
    if (!toggleDoc) await configCollection.insertOne({ _id: 'toggle', commands_enabled: true })
  } catch {}
}
connectToMongo()

app.get('/api/timeline', verifyTokenApi, requireAdminApi, async (_req, res) => {
  try {
    const entries = await timelineCollection.find().sort({ rawTimestamp: 1 }).toArray()
    res.json(entries)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/timeline', verifyTokenApi, requireAdminApi, async (req, res) => {
  try {
    const update = req.body || {}
    const lastEntryArray = await timelineCollection.find().sort({ rawTimestamp: -1 }).limit(1).toArray()
    if (lastEntryArray.length > 0) {
      const lastEntry = lastEntryArray[0]
      const lastMinute = Math.floor(Number(lastEntry.rawTimestamp || 0) / 60000)
      const newMinute = Math.floor(Number(update.rawTimestamp || 0) / 60000)
      if (lastMinute === newMinute) return res.json({ status: 'duplicate' })
    }
    await timelineCollection.insertOne(update)
    const count = await timelineCollection.countDocuments()
    const MAX_MINUTES = 60
    if (count > MAX_MINUTES) {
      const excess = count - MAX_MINUTES
      const oldest = await timelineCollection.find().sort({ rawTimestamp: 1 }).limit(excess).toArray()
      const ids = oldest.map(e => e._id)
      await timelineCollection.deleteMany({ _id: { $in: ids } })
    }
    res.json({ status: 'ok' })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get('/api/toggle', verifyTokenApi, requireAdminApi, async (_req, res) => {
  try {
    const toggleDoc = await configCollection.findOne({ _id: 'toggle' })
    res.json(toggleDoc)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/toggle', verifyTokenApi, requireAdminApi, async (req, res) => {
  try {
    const data = req.body || {}
    if (typeof data.commands_enabled === 'undefined') return res.status(400).json({ status: 'error', message: "Missing 'commands_enabled' property." })
    await configCollection.updateOne({ _id: 'toggle' }, { $set: { commands_enabled: !!data.commands_enabled } }, { upsert: true })
    const toggleDoc = await configCollection.findOne({ _id: 'toggle' })
    res.json({ status: 'success', commands_enabled: !!toggleDoc?.commands_enabled })
  } catch {
    res.status(500).json({ status: 'error', message: 'Could not update configuration.' })
  }
})

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
const sessions = {}
const openAICallLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, message: { error: 'Too many requests, please try again later.' }, standardHeaders: true, legacyHeaders: false })

async function makeOpenAIRequest(messages, retries = 3, backoff = 1000) {
  try {
    const response = await openai.createChatCompletion({ model: 'gpt-3.5-turbo', messages, temperature: 0.7, max_tokens: 150 })
    return response.data.choices[0].message.content.trim()
  } catch (error) {
    if (error.response && error.response.status === 429 && retries > 0) {
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
    if (error.response && error.response.status === 429) res.status(429).json({ error: 'Too many requests. Please try again later.' })
    else res.status(500).json({ error: 'An error occurred while processing your request.' })
  }
})

app.get('/api/weather', async (req, res) => {
  const city = req.query.city
  if (!city) return res.status(400).json({ error: 'City is required' })
  if (!OPENWEATHER_API_KEY) return res.status(500).json({ error: 'Weather service not configured.' })

  try {
    const resp = await axios.get(`https://api.openweathermap.org/data/2.5/weather?q=${encodeURIComponent(city)}&units=metric&appid=${OPENWEATHER_API_KEY}`)
    const { weather, main, wind, sys, name, coord } = resp.data
    res.json({
      city: name,
      country: sys.country,
      temperature: main.temp,
      feels_like: main.feels_like,
      humidity: main.humidity,
      wind_speed: wind.speed,
      condition: weather[0].description,
      coordinates: coord
    })
  } catch {
    res.status(500).json({ error: `Could not fetch weather for "${city}".` })
  }
})

app.get('/api/videos/public', async (_req, res) => {
  try {
    res.json([])
  } catch {
    res.status(500).send({ error: 'Error retrieving video metadata' })
  }
})

app.post('/api/videos', verifyTokenApi, requireAdminApi, [
  body('url').isURL().withMessage('Invalid URL format'),
  body('title').isString().notEmpty().withMessage('Title is required'),
  body('description').isString().optional(),
  body('category').isString().notEmpty().withMessage('Category is required')
], async (req, res) => {
  const errors = validationResult(req)
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() })

  const sanitizedUrl = String(req.body.url || '').replace('youtu.be', 'youtube.com/embed')
  const videoMetadata = {
    url: sanitizedUrl,
    title: req.body.title,
    description: req.body.description ? req.body.description : '',
    category: req.body.category,
    uploadedAt: new Date()
  }

  try {
    logger.info(`New video added: ${JSON.stringify(videoMetadata)}`)
    res.status(201).json({ message: 'Video added successfully', video: videoMetadata })
  } catch {
    res.status(500).json({ error: 'Error saving video metadata' })
  }
})

server.listen(PORT, () => { logger.info(`Server is running on port ${PORT}`) })
