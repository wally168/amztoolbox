import { db } from '@/lib/db'
import crypto from 'crypto'
import fs from 'fs'
import path from 'path'

export const SESSION_COOKIE = 'admin_session'
const globalForAuth = globalThis as unknown as { memSessions?: Map<string, { userId: string, username: string, expiresAt: Date }> }
const memSessions: Map<string, { userId: string, username: string, expiresAt: Date }> = globalForAuth.memSessions ?? new Map()
globalForAuth.memSessions = memSessions

const dataDir = path.join(process.cwd(), '.data')
const adminFile = path.join(dataDir, 'admin.json')

function readFileAdmin(): { username: string; passwordHash: string; passwordSalt: string } | null {
  try {
    const raw = fs.readFileSync(adminFile, 'utf-8')
    const obj = JSON.parse(raw)
    if (obj && typeof obj.username === 'string' && typeof obj.passwordHash === 'string' && typeof obj.passwordSalt === 'string') return obj
  } catch {}
  return null
}

function writeFileAdmin(admin: { username: string; passwordHash: string; passwordSalt: string }) {
  try {
    if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true })
    fs.writeFileSync(adminFile, JSON.stringify(admin))
  } catch {}
}

function hash(password: string, salt: string) {
  return crypto.scryptSync(password, salt, 64).toString('hex')
}

export function hashPassword(password: string) {
  const salt = crypto.randomBytes(16).toString('hex')
  const h = hash(password, salt)
  return { hash: h, salt }
}

export function verifyPassword(password: string, passwordHash: string, passwordSalt: string) {
  const h = hash(password, passwordSalt)
  return crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(passwordHash, 'hex'))
}

export async function ensureDefaultAdmin() {
  try {
    const existing = await db.adminUser.findFirst()
    if (!existing) {
      const { hash, salt } = hashPassword('dage168')
      await db.adminUser.create({ data: { username: 'dage666', passwordHash: hash, passwordSalt: salt } })
    }
  } catch {}
  const fileAdmin = readFileAdmin()
  if (!fileAdmin) {
    const { hash, salt } = hashPassword('dage168')
    writeFileAdmin({ username: 'dage666', passwordHash: hash, passwordSalt: salt })
  }
}

export async function authenticate(username: string, password: string) {
  // First, try to find user in DB
  try {
    const user = await db.adminUser.findUnique({ where: { username } })
    if (user) {
      const ok = verifyPassword(password, user.passwordHash, user.passwordSalt)
      return ok ? user : null
    }
  } catch (e) {
    console.error('DB Auth Error:', e)
    // Continue to check default admin if DB fails or user not found
  }

  // Check default admin credentials
  const defaultUser = process.env.ADMIN_USERNAME || 'dage666'
  const defaultPass = process.env.ADMIN_PASSWORD || 'dage168'

  if (username === defaultUser && password === defaultPass) {
    // If DB is reachable, we MUST sync this default user to DB to support sessions
    try {
      const { hash, salt } = hashPassword(defaultPass)
      const dbUser = await db.adminUser.upsert({
        where: { username: defaultUser },
        update: {}, // Don't update password if it exists
        create: { username: defaultUser, passwordHash: hash, passwordSalt: salt }
      })
      return dbUser
    } catch (e) {
      console.error('DB Upsert Error:', e)
      // If we are in production and DB fails, we should fail hard because memory sessions won't work
      if (process.env.NODE_ENV === 'production') {
        throw new Error('Database unreachable in production. Cannot persist session.')
      }
    }
    // Fallback for local dev only
    return { id: 'default-admin', username: defaultUser, passwordHash: '', passwordSalt: '' } as any
  }
  
  return null
}

export async function createSession(userId: string, username: string) {
  const token = crypto.randomUUID()
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
  
  // Always try to persist session to DB
  try { 
    await db.session.create({ data: { token, userId, expiresAt } }) 
  } catch (e) {
    console.error('Session Persistence Error:', e)
    if (process.env.NODE_ENV === 'production') {
      // If we cannot persist session in DB, login is invalid in serverless
      throw new Error('Failed to persist session: ' + String(e))
    }
  }
  
  // Keep memory session for local dev or fallback
  memSessions.set(token, { userId, username, expiresAt })
  return { token, expiresAt }
}

export async function getSessionByToken(token: string) {
  try {
    const session = await db.session.findUnique({ where: { token }, include: { user: true } })
    if (session) {
      if (session.expiresAt.getTime() < Date.now()) {
        try { await db.session.delete({ where: { token } }) } catch {}
        return null
      }
      return session
    }
  } catch {}
  const mem = memSessions.get(token)
  if (!mem) return null
  if (mem.expiresAt.getTime() < Date.now()) { memSessions.delete(token); return null }
  return { id: token, token, userId: mem.userId, expiresAt: mem.expiresAt, user: { id: mem.userId, username: mem.username } } as any
}

export async function destroySession(token: string) {
  try { await db.session.delete({ where: { token } }) } catch {}
  memSessions.delete(token)
}

export function buildCookieOptions(expiresAt: Date) {
  return {
    httpOnly: true,
    sameSite: 'lax' as const,
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    expires: expiresAt
  }
}

export function getFileAdmin(): { username: string; passwordHash: string; passwordSalt: string } | null {
  return readFileAdmin()
}

export function setFileAdmin(admin: { username: string; passwordHash: string; passwordSalt: string }) {
  writeFileAdmin(admin)
}