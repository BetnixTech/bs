// betnix-security.js
// A unified security toolkit for Betnix systems
// Dependencies: express, argon2, jsonwebtoken, helmet, express-rate-limit, uuid, winston, cookie-parser

import express from 'express';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import winston from 'winston';
import fs from 'fs';
import path from 'path';

// ---------- Password Hashing ----------
const DEFAULT_OPTS = {
  type: argon2.argon2id,
  memoryCost: 2 ** 16,
  timeCost: 3,
  parallelism: 1
};

export async function hashPassword(plain) {
  return argon2.hash(plain, DEFAULT_OPTS);
}

export async function verifyPassword(hash, plain) {
  return argon2.verify(hash, plain);
}

// ---------- Token Auth + Refresh ----------
const REFRESH_STORE = new Map(); // userId -> Map of tokenId -> meta
const ACCESS_EXPIRES = '15m';
const REFRESH_EXPIRES_MS = 1000 * 60 * 60 * 24 * 7; // 7 days

export function generateAccessToken(user, secret) {
  const payload = {
    sub: user.id,
    roles: user.roles || [],
    iat: Math.floor(Date.now() / 1000)
  };
  return jwt.sign(payload, secret, { expiresIn: ACCESS_EXPIRES });
}

export function issueRefreshToken(userId) {
  const tokenId = uuidv4();
  const meta = { tokenId, userId, issuedAt: Date.now() };
  if (!REFRESH_STORE.has(userId)) REFRESH_STORE.set(userId, new Map());
  REFRESH_STORE.get(userId).set(tokenId, meta);
  return { tokenId, meta };
}

export function rotateRefreshToken(userId, tokenId) {
  const userMap = REFRESH_STORE.get(userId);
  if (!userMap) return null;
  const meta = userMap.get(tokenId);
  if (!meta) return null;

  // remove old token
  userMap.delete(tokenId);
  addAudit({ type: 'refresh_rotated', userId, tokenId, ts: Date.now() });

  return issueRefreshToken(userId);
}

export function revokeAllRefreshTokens(userId) {
  REFRESH_STORE.delete(userId);
  addAudit({ type: 'refresh_revoked_all', userId, ts: Date.now() });
}

export function requireAuth(secret) {
  return function (req, res, next) {
    const h = req.headers.authorization;
    if (!h || !h.startsWith('Bearer '))
      return res.status(401).json({ error: 'Missing token' });
    const token = h.slice(7);
    try {
      const payload = jwt.verify(token, secret);
      req.user = { id: payload.sub, roles: payload.roles || [] };
      next();
    } catch {
      return res.status(401).json({ error: 'Invalid token' });
    }
  };
}

// ---------- RBAC ----------
export function requireRole(role) {
  return function (req, res, next) {
    const roles = (req.user && req.user.roles) || [];
    if (roles.includes(role)) return next();
    return res.status(403).json({ error: 'Forbidden' });
  };
}

// ---------- Rate Limiting ----------
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many auth attempts, slow down' },
  standardHeaders: true,
  legacyHeaders: false
});

// ---------- Secure Headers ----------
export function secureHeaders(app) {
  app.use(helmet());
  app.use(
    helmet.contentSecurityPolicy({
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"]
      }
    })
  );
}

// ---------- Audit Logging ----------
const auditDir = path.resolve(process.cwd(), 'logs');
if (!fs.existsSync(auditDir)) fs.mkdirSync(auditDir);

const auditLogger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: path.join(auditDir, 'audit.log') })
  ]
});

export function addAudit(obj) {
  auditLogger.info(obj);
}

// ---------- Example Setup ----------
export function createSecureApp(secret) {
  const app = express();
  app.use(express.json());
  app.use(cookieParser());
  secureHeaders(app);

  // Example signup
  app.post('/signup', async (req, res) => {
    const { email, password } = req.body;
    const pwHash = await hashPassword(password);
    // Save user {email, pwHash} into DB...
    res.json({ ok: true });
  });

  // Example login
  app.post('/login', authLimiter, async (req, res) => {
    // lookup user in DB and verify password...
    const user = { id: 'user-123', roles: ['user'] };
    const access = generateAccessToken(user, secret);
    const { tokenId } = issueRefreshToken(user.id);
    res.cookie('r', tokenId, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: REFRESH_EXPIRES_MS
    });
    res.json({ access });
  });

  // Refresh endpoint
  app.post('/token', (req, res) => {
    const tokenId = req.cookies.r;
    const userId = 'user-123'; // look up from DB/session
    const rotated = rotateRefreshToken(userId, tokenId);
    if (!rotated) return res.status(401).json({ error: 'Invalid refresh token' });
    const access = generateAccessToken({ id: userId, roles: ['user'] }, secret);
    res.cookie('r', rotated.tokenId, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: REFRESH_EXPIRES_MS
    });
    res.json({ access });
  });

  // Protected route
  app.get('/me', requireAuth(secret), (req, res) => {
    res.json({ user: req.user });
  });

  return app;
}
