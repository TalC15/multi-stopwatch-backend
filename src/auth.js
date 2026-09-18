import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import supabase from './db.js';

const JWT_SECRET = process.env.JWT_SECRET;
const SALT_ROUNDS = 10;

// PIN hashle
export async function hashPin(pin) {
  return await bcrypt.hash(pin, SALT_ROUNDS);
}

// PIN doğrula
export async function verifyPin(pin, hash) {
  return await bcrypt.compare(pin, hash);
}

// Refresh token'ı DB'de ham haliyle değil, hash'iyle saklıyoruz (güvenlik)
export function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// Access token — id + sessionId
export function generateAccessToken(user, sessionId) {
  return jwt.sign(
    { id: user.id, sessionId },
    JWT_SECRET,
    { expiresIn: '15m' }
  );
}

// Refresh token — id + sessionId
export function generateRefreshToken(user, sessionId) {
  return jwt.sign(
    { id: user.id, sessionId },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}

// Token doğrula
export function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

// Middleware — her korumalı route'da kullanılacak
// Kullanıcıyı DB'den al + oturumun iptal edilip edilmediğini kontrol et
export async function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token gerekli' });
  }

  const token = authHeader.split(' ')[1];
  const decoded = verifyToken(token);

  if (!decoded) {
    return res.status(401).json({ error: 'Geçersiz veya süresi dolmuş token' });
  }

  try {
    const [userResult, sessionResult] = await Promise.all([
      supabase
        .from('users')
        .select('id, username, role, workspace_id')
        .eq('id', decoded.id)
        .single(),
      decoded.sessionId
        ? supabase
            .from('sessions')
            .select('id, revoked_at')
            .eq('id', decoded.sessionId)
            .single()
        : Promise.resolve({ data: null, error: { code: 'NO_SESSION_ID' } }),
    ]);

    if (userResult.error || !userResult.data) {
      // "Satır bulunamadı" → gerçekten geçersiz kullanıcı → 401
      // Başka türlü hata (bağlantı vb.) → geçici altyapı sorunu → 503
      const status = userResult.error?.code === 'PGRST116' ? 401 : 503;
      return res.status(status).json({ error: 'Kullanıcı doğrulanamadı' });
    }

    if (sessionResult.error) {
      if (
        sessionResult.error.code === 'PGRST116' ||
        sessionResult.error.code === 'NO_SESSION_ID'
      ) {
        return res
          .status(401)
          .json({ error: 'Oturum sona ermiş, tekrar giriş yapın' });
      }
      return res
        .status(503)
        .json({ error: 'Sunucu geçici olarak erişilemiyor' });
    }

    if (!sessionResult.data || sessionResult.data.revoked_at) {
      return res
        .status(401)
        .json({ error: 'Oturum sona ermiş, tekrar giriş yapın' });
    }

    req.user = userResult.data;
    req.sessionId = decoded.sessionId;
    next();
  } catch (err) {
    console.error('[authenticate] beklenmeyen hata:', err);
    return res.status(503).json({ error: 'Sunucu geçici olarak erişilemiyor' });
  }
}

// Middleware — rol kontrolü
export function authorize(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Bu işlem için yetkiniz yok' });
    }
    next();
  };
}

// Superadmin ilk kurulumda otomatik oluştur
export async function createSuperAdminIfNotExists() {
  const { data: existing } = await supabase
    .from('users')
    .select('id')
    .eq('role', 'superadmin')
    .single();

  if (existing) {
    console.log('[Auth] Superadmin zaten mevcut');
    return;
  }

  const pin = process.env.SUPERADMIN_PIN || '1234';
  const pin_hash = await hashPin(pin);

  const { error } = await supabase
    .from('users')
    .insert({
      username: 'admin',
      pin_hash,
      role: 'superadmin',
    });

  if (error) {
    console.error('[Auth] Superadmin oluşturulamadı:', error);
  } else {
    console.log('[Auth] Superadmin oluşturuldu — kullanıcı adı: admin, PIN:', pin);
  }
}