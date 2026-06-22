import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
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

// Sadece id sakla
export function generateAccessToken(user) {
  return jwt.sign(
    { id: user.id },
    JWT_SECRET,
    { expiresIn: '15m' }
  );
}

export function generateRefreshToken(user) {
  return jwt.sign(
    { id: user.id },
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
// Role DB'den al
export function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token gerekli' });
  }

  const token = authHeader.split(' ')[1];
  const decoded = verifyToken(token);

  if (!decoded) {
    return res.status(401).json({ error: 'Geçersiz veya süresi dolmuş token' });
  }

  supabase
    .from('users')
    .select('id, username, role, workspace_id')
    .eq('id', decoded.id)
    .single()
    .then(({ data, error }) => {
      if (error || !data) {
        return res.status(401).json({ error: 'Kullanıcı bulunamadı' });
      }
      req.user = data;
      next();
    });
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