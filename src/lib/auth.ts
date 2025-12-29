import { db } from '@/lib/db'
import crypto from 'crypto'

export const SESSION_COOKIE = 'admin_session'

// Simple in-memory cache for development only
const globalForAuth = globalThis as unknown as { memSessions?: Map<string, { userId: string, username: string, expiresAt: Date }> }
const memSessions: Map<string, { userId: string, username: string, expiresAt: Date }> = globalForAuth.memSessions ?? new Map()
if (process.env.NODE_ENV !== 'production') globalForAuth.memSessions = memSessions

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
      await db.adminUser.create({ 
        data: { 
          username: 'dage666', 
          passwordHash: hash, 
          passwordSalt: salt 
        } 
      })
      console.log('Default admin created')
    }
  } catch (e) {
    console.error('Failed to ensure default admin:', e)
    // Do not throw here, as we might still be able to authenticate via fallback if implemented,
    // but for production this usually means DB is down.
  }
}

export async function authenticate(username: string, password: string) {
  // 1. Try to find user in DB
  try {
    const user = await db.adminUser.findUnique({ where: { username } })
    if (user) {
      const ok = verifyPassword(password, user.passwordHash, user.passwordSalt)
      return ok ? user : null
    }
  } catch (e) {
    console.error('DB Auth Error:', e)
  }

  // 2. Check default admin credentials (env vars or hardcoded)
  // This is a fallback or for initial setup if DB is empty/unreachable but we want to try to sync
  const defaultUser = process.env.ADMIN_USERNAME || 'dage666'
  const defaultPass = process.env.ADMIN_PASSWORD || 'dage168'

  if (username === defaultUser && password === defaultPass) {
    // If we matched default credentials, we MUST ensure this user exists in DB for session persistence
    try {
      const { hash, salt } = hashPassword(defaultPass)
      const dbUser = await db.adminUser.upsert({
        where: { username: defaultUser },
        update: {}, // User exists, just return it (or we could update password if we wanted to enforce env var)
        create: { username: defaultUser, passwordHash: hash, passwordSalt: salt }
      })
      return dbUser
    } catch (e) {
      console.error('DB Upsert Error:', e)
      // In production, we cannot proceed without DB persistence
      if (process.env.NODE_ENV === 'production') {
        throw new Error('Database unreachable in production. Cannot persist session.')
      }
    }
    
    // Dev only fallback
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
      throw new Error('Failed to persist session: ' + String(e))
    }
  }
  
  // Keep memory session for local dev
  if (process.env.NODE_ENV !== 'production') {
    memSessions.set(token, { userId, username, expiresAt })
  }
  
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
  } catch (e) {
    console.error('Get Session Error:', e)
  }
  
  // Dev fallback
  if (process.env.NODE_ENV !== 'production') {
    const mem = memSessions.get(token)
    if (!mem) return null
    if (mem.expiresAt.getTime() < Date.now()) { memSessions.delete(token); return null }
    return { id: token, token, userId: mem.userId, expiresAt: mem.expiresAt, user: { id: mem.userId, username: mem.username } } as any
  }
  
  return null
}

export async function destroySession(token: string) {
  try { await db.session.delete({ where: { token } }) } catch {}
  if (process.env.NODE_ENV !== 'production') {
    memSessions.delete(token)
  }
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
