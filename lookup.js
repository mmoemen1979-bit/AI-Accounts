const { Pool } = require('pg');
const { normalizeName, hashNationalId, decryptPassword, validNationalId } = require('../src/security');
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'false' ? false : { rejectUnauthorized: false },
  max: 3,
  idleTimeoutMillis: 10000
});
const attempts = new Map();

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  const route = (req.url || '').split('?')[0];
  if (req.method === 'GET' && route === '/api/health') {
    try { await pool.query('SELECT 1'); return res.status(200).json({ status: 'ok' }); }
    catch { return res.status(503).json({ status: 'unavailable' }); }
  }
  if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return res.status(405).json({ error: 'Method not allowed' }); }
  if (!process.env.DATABASE_URL || !process.env.NATIONAL_ID_HMAC_KEY || !process.env.PASSWORD_ENCRYPTION_KEY) {
    return res.status(500).json({ error: 'إعدادات الخادم غير مكتملة. يرجى التواصل مع مسؤول النظام.' });
  }
  const ip = String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim();
  const now = Date.now();
  const recent = (attempts.get(ip) || []).filter(t => now - t < 900000);
  if (recent.length >= 8) return res.status(429).json({ error: 'تم تجاوز عدد المحاولات المسموح بها. حاول مرة أخرى بعد قليل.' });
  recent.push(now); attempts.set(ip, recent);
  let body = req.body;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch { body = {}; } }
  if (!body || typeof body !== 'object') body = {};
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  const nationalId = typeof body.nationalId === 'string' ? body.nationalId.replace(/\s/g, '') : '';
  if (!name || name.length > 180 || !validNationalId(nationalId)) return res.status(400).json({ error: 'يرجى إدخال الاسم والرقم القومي المكوّن من 14 رقمًا بصورة صحيحة.' });
  const normalized = normalizeName(name);
  if (normalized.length < 6) return res.status(400).json({ error: 'يرجى إدخال الاسم الكامل كما هو مسجل بالمدرسة.' });
  try {
    const result = await pool.query(
      'SELECT student_name, student_code, username, password_encrypted FROM students WHERE name_normalized = $1 AND national_id_hash = $2 LIMIT 2',
      [normalized, hashNationalId(nationalId)]
    );
    if (result.rowCount !== 1) return res.status(404).json({ error: 'تعذر التحقق من البيانات المدخلة. راجع الاسم والرقم القومي وحاول مرة أخرى.' });
    const student = result.rows[0];
    const password = decryptPassword(student.password_encrypted);
    return res.status(200).json({ studentName: student.student_name, studentCode: String(student.student_code ?? ''), username: String(student.username ?? ''), password });
  } catch {
    console.error('Student lookup failed.');
    return res.status(500).json({ error: 'حدث خطأ أثناء التحقق. تحقق من إعداد قاعدة البيانات ومفاتيح التشفير.' });
  }
};
