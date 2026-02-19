require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const { Pool } = require('pg');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nml-secret-v3';
const ADMIN_PASSWORD_HASH = bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 10);
const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const BOT_SECRET = process.env.BOT_SECRET || 'nml-bot-secret';
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '1473368731571978433';
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || 'csRtGIfrvLJCaA7ENaN7VNrXz5wfc_Vz';
const OWNER_ID = '1429171703879307277';
const INQUIRY_CHANNEL = '1472992778173812756';
const ADMIN_CHANNEL = '1472988444220461240';
const STORE_URL = process.env.RAILWAY_PUBLIC_DOMAIN
  ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
  : `http://localhost:${PORT}`;

const ALL_THEMES = ['yellow','red','blue','green','white','orange','pink','rainbow','blackwhite','black'];
const FREE_THEMES = ['yellow'];

// ── PostgreSQL ─────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.PG_URL || process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ── DB INIT ────────────────────────────────────────────────────
async function initDB() {
  const client = await pool.connect();
  try {
    // Products
    await client.query(`CREATE TABLE IF NOT EXISTS products (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL, description TEXT DEFAULT '',
      price NUMERIC(10,2) NOT NULL DEFAULT 0, original_price NUMERIC(10,2),
      category TEXT DEFAULT 'Accounts', image TEXT, badge TEXT,
      stock INTEGER DEFAULT 999, featured BOOLEAN DEFAULT false,
      coming_soon BOOLEAN DEFAULT false, views INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
    )`);

    await client.query(`CREATE TABLE IF NOT EXISTS product_variants (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      product_id UUID REFERENCES products(id) ON DELETE CASCADE,
      name TEXT NOT NULL, price NUMERIC(10,2) NOT NULL,
      original_price NUMERIC(10,2), stock INTEGER DEFAULT 999,
      sort_order INTEGER DEFAULT 0, created_at TIMESTAMPTZ DEFAULT NOW()
    )`);

    // Users (Discord OAuth)
    await client.query(`CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL, discriminator TEXT, avatar TEXT,
      owned_themes TEXT[] DEFAULT ARRAY['yellow'],
      active_theme TEXT DEFAULT 'yellow',
      custom_color1 TEXT, custom_color2 TEXT,
      is_member BOOLEAN DEFAULT false,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )`);

    // Inquiries
    await client.query(`CREATE TABLE IF NOT EXISTS inquiries (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      product_id UUID, product_name TEXT NOT NULL,
      product_price NUMERIC(10,2) DEFAULT 0, variant_name TEXT,
      discord_username TEXT DEFAULT 'Unknown', discord_id TEXT,
      coupon_code TEXT, discount_amount NUMERIC(10,2) DEFAULT 0,
      final_price NUMERIC(10,2) DEFAULT 0, note TEXT,
      status TEXT DEFAULT 'pending', created_at TIMESTAMPTZ DEFAULT NOW()
    )`);

    // Coupons with expiry
    await client.query(`CREATE TABLE IF NOT EXISTS coupons (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      code TEXT UNIQUE NOT NULL, discount_percent NUMERIC(5,2) NOT NULL,
      max_uses INTEGER DEFAULT 0, uses INTEGER DEFAULT 0,
      active BOOLEAN DEFAULT true,
      expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);

    // Announcements
    await client.query(`CREATE TABLE IF NOT EXISTS announcements (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      message TEXT NOT NULL, active BOOLEAN DEFAULT true,
      color TEXT DEFAULT 'yellow', created_at TIMESTAMPTZ DEFAULT NOW()
    )`);

    // Waitlist
    await client.query(`CREATE TABLE IF NOT EXISTS waitlist (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      product_id UUID, product_name TEXT NOT NULL,
      discord_username TEXT NOT NULL, notified BOOLEAN DEFAULT false,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);

    // Migrations for existing tables
    const migrations = [
      `ALTER TABLE products ADD COLUMN IF NOT EXISTS original_price NUMERIC(10,2)`,
      `ALTER TABLE products ADD COLUMN IF NOT EXISTS views INTEGER DEFAULT 0`,
      `ALTER TABLE coupons ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ`,
    ];
    for (const m of migrations) await client.query(m).catch(() => {});

    const { rows } = await client.query('SELECT COUNT(*) FROM products');
    if (parseInt(rows[0].count) === 0) await seedProducts(client);

    console.log('✅ Database ready');
  } finally { client.release(); }
}

async function seedProducts(client) {
  const products = [
    { id: '12f92f56-34b7-4a8a-b0f5-45e9ca8dbcc5', name: 'Amazon Prime Video Premium', description: '- Full Access to AMZ Prime Video Premium!\n- Lifetime subscription, $0 fees!\n- 12 Months (reoccurring)\n- Checked accounts! User and Pass\n- Email, Phone, etc. and Pass CAN be changed!\n- NO RESELLING!', price: 1.10, category: 'Accounts', image: '/uploads/b15c251d-45ed-48a7-9028-281de7f19ed9.png', badge: null, stock: 93, featured: true },
    { id: 'a6e11dd5-a2c9-433c-abc2-78ba8b036a63', name: 'Spotify Premium', description: '- Full Access to Spotify Premium\n- 12 Months (reoccurring)\n- NO RESELLING!', price: 1.80, category: 'Accounts', image: '/uploads/cd444c5a-aa87-45cb-8759-32e7adfbb916.png', badge: 'HOT', stock: 87, featured: true },
    { id: '28998b63-669d-44da-867c-1e30432740c6', name: 'Crunchyroll Premium', description: '- Full Access to CR Premium\n- 12 Months (reoccurring)\n- NO RESELLING!', price: 0.12, category: 'Accounts', image: '/uploads/de1540a1-0563-4f7d-af2d-3759d3f32d26.png', badge: null, stock: 100, featured: true },
    { id: '2d6df3ec-274d-46d1-8255-78f3c4b27307', name: 'Netflix Premium', description: '- Full Access to Netflix Premium\n- 12 Months (reoccurring)\n- NO RESELLING!', price: 0.25, category: 'Accounts', image: '/uploads/9e1dc7bc-f84e-43ed-9c2f-5a31ce4ff850.png', badge: 'NEW', stock: 100, featured: true },
    { id: '4a9b3bbb-6ece-4c2a-809e-0c1dd3d88c7b', name: '14x Server Boosts (1 MONTH)', description: '- 14x Server Boosts for 1 Month!\n- NOT reoccurring\n- NO RESELLING!', price: 2.25, category: 'Other', image: '/uploads/51b23eb3-e0a4-4908-9f0d-400ddaebb161.png', badge: 'HOT', stock: 999, featured: true },
    { id: '0d8ea7ca-d99c-4ac7-9070-b91b92690eaa', name: '1K Discord Server Members', description: 'Coming soon!', price: 0, category: 'Software', image: '/uploads/48fb0798-85af-43bf-9b53-9c26550537bb.png', badge: 'SOON', stock: 0, coming_soon: true },
    { id: 'f504a483-c37c-4204-aa89-3c5d8d066f9e', name: 'HBO Max Premium', description: '- Full Access to HBO Max Premium\n- 12 Months (reoccurring)\n- NO RESELLING!', price: 0.33, category: 'Accounts', image: '/uploads/4464bb4a-16f1-464e-81a7-69b56615f0d7.png', badge: 'NEW', stock: 121 },
    { id: '4bf8b2bc-461e-4028-bbd3-de0cbf7abc75', name: 'Steam Premium', description: '- Full Access to STEAM Premium\n- 12 Months (reoccurring)\n- NO RESELLING!', price: 0.19, category: 'Accounts', image: '/uploads/63caa547-d6e7-4d0f-85f1-12f0ce59ee78.png', badge: 'SALE', stock: 78 },
    { id: '50d7ad68-11d1-4206-b1b5-680167f36fe6', name: 'CapCut Premium', description: '- Full Access to CapCut Premium (PRO)\n- 12 Months (reoccurring)\n- NO RESELLING!', price: 0.32, category: 'Accounts', image: '/uploads/3a818cd3-077a-4fb3-b14d-c636a1af341a.png', badge: null, stock: 62 },
    { id: '7867c87f-9340-4001-9108-c26a2460ba55', name: 'Paramount+ Premium', description: '- Full Access to Paramount+ Premium\n- 12 Months (reoccurring)\n- NO RESELLING!', price: 0.12, category: 'Accounts', image: '/uploads/fccd9b4a-479b-491c-aff0-24ae6931c833.png', badge: 'NEW', stock: 150 },
    { id: '3953e1f0-8311-4c8b-b043-b3119e889dae', name: 'YouTube Premium', description: '- Full Access to YT Premium\n- 12 Months (reoccurring)\n- NO RESELLING!', price: 0.35, category: 'Accounts', image: '/uploads/31a07239-74c0-43d7-85cc-f213d1ec861c.png', badge: 'SALE', stock: 100 }
  ];
  for (const p of products) {
    await client.query(`INSERT INTO products (id,name,description,price,category,image,badge,stock,featured,coming_soon) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (id) DO NOTHING`,
      [p.id, p.name, p.description, p.price, p.category, p.image, p.badge||null, p.stock||999, p.featured||false, p.coming_soon||false]);
  }
  console.log('✅ Seeded 11 products');
}

// ── Middleware ─────────────────────────────────────────────────
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
app.use('/uploads', express.static(uploadsDir));
app.use(express.static(path.join(__dirname, 'public')));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname)}`)
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 }, fileFilter: (req, file, cb) => cb(null, /jpeg|jpg|png|gif|webp/.test(file.mimetype)) });

function requireAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const d = jwt.verify(auth.split(' ')[1], JWT_SECRET);
    if (d.role !== 'admin') throw new Error();
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

function requireUser(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Not logged in' });
  try {
    const d = jwt.verify(auth.split(' ')[1], JWT_SECRET);
    req.user = d;
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

async function sendDiscordEmbed(channelId, embeds) {
  if (!BOT_TOKEN) return;
  try {
    await fetch(`https://discord.com/api/v10/channels/${channelId}/messages`, {
      method: 'POST',
      headers: { 'Authorization': `Bot ${BOT_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ embeds })
    });
  } catch (e) { console.error('[Discord]', e.message); }
}

function fmtProduct(r) {
  return {
    id: r.id, name: r.name, description: r.description,
    price: parseFloat(r.price), original_price: r.original_price ? parseFloat(r.original_price) : null,
    category: r.category, image: r.image, badge: r.badge,
    stock: r.stock, featured: r.featured, coming_soon: r.coming_soon,
    views: r.views || 0, createdAt: r.created_at, updatedAt: r.updated_at
  };
}

// ══════════════════════════════════════════════════════════════
// DISCORD OAUTH
// ══════════════════════════════════════════════════════════════

app.get('/auth/discord', (req, res) => {
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: `${STORE_URL}/auth/discord/callback`,
    response_type: 'code',
    scope: 'identify'
  });
  res.redirect(`https://discord.com/api/oauth2/authorize?${params}`);
});

app.get('/auth/discord/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.redirect('/?error=no_code');

  try {
    // Exchange code for token
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: `${STORE_URL}/auth/discord/callback`
      })
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error('No access token');

    // Get user info
    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { 'Authorization': `Bearer ${tokenData.access_token}` }
    });
    const discordUser = await userRes.json();

    // Upsert user in DB
    const { rows } = await pool.query(`
      INSERT INTO users (id, username, discriminator, avatar)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (id) DO UPDATE SET
        username = EXCLUDED.username,
        discriminator = EXCLUDED.discriminator,
        avatar = EXCLUDED.avatar,
        updated_at = NOW()
      RETURNING *
    `, [discordUser.id, discordUser.username, discordUser.discriminator || '0', discordUser.avatar]);

    const user = rows[0];

    // Generate JWT for user
    const token = jwt.sign({
      role: 'user',
      id: user.id,
      username: user.username,
      avatar: user.avatar,
      is_member: user.is_member,
      owned_themes: user.owned_themes,
      active_theme: user.active_theme,
      custom_color1: user.custom_color1,
      custom_color2: user.custom_color2
    }, JWT_SECRET, { expiresIn: '7d' });

    // Redirect back to store with token
    res.redirect(`/?token=${token}`);
  } catch (e) {
    console.error('[OAuth]', e.message);
    res.redirect('/?error=auth_failed');
  }
});

// Get current user profile
app.get('/api/me', requireUser, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [req.user.id]);
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    const u = rows[0];
    res.json({
      id: u.id, username: u.username, avatar: u.avatar,
      owned_themes: u.owned_themes, active_theme: u.active_theme,
      custom_color1: u.custom_color1, custom_color2: u.custom_color2,
      is_member: u.is_member
    });
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

// Update user theme
app.post('/api/me/theme', requireUser, async (req, res) => {
  const { theme, custom_color1, custom_color2 } = req.body;
  try {
    const { rows: userRows } = await pool.query('SELECT * FROM users WHERE id=$1', [req.user.id]);
    if (!userRows.length) return res.status(404).json({ error: 'User not found' });
    const user = userRows[0];

    // Check if user owns the theme
    if (theme === 'custom') {
      if (!user.is_member) return res.status(403).json({ error: 'Membership required for custom themes' });
    } else if (!FREE_THEMES.includes(theme) && !user.owned_themes?.includes(theme)) {
      return res.status(403).json({ error: 'You don\'t own this theme' });
    }

    const { rows } = await pool.query(`
      UPDATE users SET active_theme=$1, custom_color1=$2, custom_color2=$3, updated_at=NOW()
      WHERE id=$4 RETURNING *
    `, [theme, custom_color1||null, custom_color2||null, req.user.id]);

    // Issue new token with updated theme
    const u = rows[0];
    const token = jwt.sign({
      role: 'user', id: u.id, username: u.username, avatar: u.avatar,
      is_member: u.is_member, owned_themes: u.owned_themes,
      active_theme: u.active_theme, custom_color1: u.custom_color1, custom_color2: u.custom_color2
    }, JWT_SECRET, { expiresIn: '7d' });

    res.json({ success: true, token, active_theme: u.active_theme, custom_color1: u.custom_color1, custom_color2: u.custom_color2 });
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

// ── ADMIN: Grant/revoke theme ──────────────────────────────────
app.post('/api/admin/grant-theme', requireAdmin, async (req, res) => {
  const { discord_id, theme } = req.body;
  if (!discord_id || !theme) return res.status(400).json({ error: 'discord_id and theme required' });
  try {
    const { rows } = await pool.query(`
      UPDATE users SET owned_themes = array_append(array_remove(owned_themes, $1), $1), updated_at=NOW()
      WHERE id=$2 RETURNING *
    `, [theme, discord_id]);
    if (!rows.length) return res.status(404).json({ error: 'User not found — they must log in first' });
    res.json({ success: true, owned_themes: rows[0].owned_themes });
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.post('/api/admin/revoke-theme', requireAdmin, async (req, res) => {
  const { discord_id, theme } = req.body;
  try {
    const { rows } = await pool.query(`
      UPDATE users SET owned_themes = array_remove(owned_themes, $1), updated_at=NOW()
      WHERE id=$2 RETURNING *
    `, [theme, discord_id]);
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true, owned_themes: rows[0].owned_themes });
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.post('/api/admin/membership', requireAdmin, async (req, res) => {
  const { discord_id, action } = req.body; // action: 'give' or 'revoke'
  try {
    const isMember = action === 'give';
    const { rows } = await pool.query(`
      UPDATE users SET is_member=$1, updated_at=NOW() WHERE id=$2 RETURNING *
    `, [isMember, discord_id]);
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true, is_member: rows[0].is_member });
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

// ══════════════════════════════════════════════════════════════
// PRODUCTS
// ══════════════════════════════════════════════════════════════

app.get('/api/health', (req, res) => res.json({ status: 'online', store: "No Man's Land" }));

app.post('/api/admin/login', async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });
  const valid = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
  if (!valid) return res.status(401).json({ error: 'Wrong password' });
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token });
});

app.get('/api/products', async (req, res) => {
  try {
    const { search } = req.query;
    let query = 'SELECT * FROM products';
    const params = [];
    if (search) {
      query += ' WHERE LOWER(name) LIKE LOWER($1) OR LOWER(category) LIKE LOWER($1)';
      params.push(`%${search}%`);
    }
    query += ' ORDER BY featured DESC, created_at DESC';
    const { rows } = await pool.query(query, params);
    const { rows: variants } = await pool.query('SELECT * FROM product_variants ORDER BY sort_order ASC');
    res.json(rows.map(p => ({ ...fmtProduct(p), variants: variants.filter(v => v.product_id === p.id).map(v => ({ id: v.id, name: v.name, price: parseFloat(v.price), original_price: v.original_price ? parseFloat(v.original_price) : null, stock: v.stock, sort_order: v.sort_order })) })));
  } catch (e) { console.error(e); res.status(500).json({ error: 'DB error' }); }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM products WHERE id=$1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    await pool.query('UPDATE products SET views = COALESCE(views,0) + 1 WHERE id=$1', [req.params.id]);
    const { rows: variants } = await pool.query('SELECT * FROM product_variants WHERE product_id=$1 ORDER BY sort_order ASC', [req.params.id]);
    res.json({ ...fmtProduct(rows[0]), variants: variants.map(v => ({ id: v.id, name: v.name, price: parseFloat(v.price), original_price: v.original_price ? parseFloat(v.original_price) : null, stock: v.stock })) });
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.post('/api/products', requireAdmin, upload.single('image'), async (req, res) => {
  const { name, description, price, original_price, category, badge, stock, featured, coming_soon, variants } = req.body;
  if (!name || price === undefined) return res.status(400).json({ error: 'Name and price required' });
  try {
    const { rows } = await pool.query(`INSERT INTO products (name,description,price,original_price,category,image,badge,stock,featured,coming_soon) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [name, description||'', parseFloat(price), original_price?parseFloat(original_price):null, category||'Accounts', req.file?`/uploads/${req.file.filename}`:null, badge||null, parseInt(stock)||999, featured==='true', coming_soon==='true']);
    const product = rows[0];
    if (variants) {
      const parsed = typeof variants === 'string' ? JSON.parse(variants) : variants;
      for (let i = 0; i < parsed.length; i++) {
        const v = parsed[i];
        await pool.query(`INSERT INTO product_variants (product_id,name,price,original_price,stock,sort_order) VALUES ($1,$2,$3,$4,$5,$6)`, [product.id, v.name, parseFloat(v.price), v.original_price?parseFloat(v.original_price):null, parseInt(v.stock)||999, i]);
      }
    }
    res.status(201).json(fmtProduct(product));
  } catch (e) { console.error(e); res.status(500).json({ error: 'DB error' }); }
});

app.put('/api/products/:id', requireAdmin, upload.single('image'), async (req, res) => {
  try {
    const { rows: ex } = await pool.query('SELECT * FROM products WHERE id=$1', [req.params.id]);
    if (!ex.length) return res.status(404).json({ error: 'Not found' });
    const old = ex[0];
    if (req.file && old.image) { const p = path.join(__dirname, old.image); if (fs.existsSync(p)) fs.unlinkSync(p); }
    const { name, description, price, original_price, category, badge, stock, featured, coming_soon, variants } = req.body;
    const { rows } = await pool.query(`UPDATE products SET name=$1,description=$2,price=$3,original_price=$4,category=$5,image=$6,badge=$7,stock=$8,featured=$9,coming_soon=$10,updated_at=NOW() WHERE id=$11 RETURNING *`,
      [name??old.name, description!==undefined?description:old.description, price!==undefined?parseFloat(price):old.price, original_price!==undefined?(original_price?parseFloat(original_price):null):old.original_price, category??old.category, req.file?`/uploads/${req.file.filename}`:old.image, badge!==undefined?(badge||null):old.badge, stock!==undefined?parseInt(stock):old.stock, featured!==undefined?featured==='true':old.featured, coming_soon!==undefined?coming_soon==='true':old.coming_soon, req.params.id]);
    if (variants !== undefined) {
      await pool.query('DELETE FROM product_variants WHERE product_id=$1', [req.params.id]);
      const parsed = typeof variants === 'string' ? JSON.parse(variants) : variants;
      for (let i = 0; i < parsed.length; i++) {
        const v = parsed[i];
        await pool.query(`INSERT INTO product_variants (product_id,name,price,original_price,stock,sort_order) VALUES ($1,$2,$3,$4,$5,$6)`, [req.params.id, v.name, parseFloat(v.price), v.original_price?parseFloat(v.original_price):null, parseInt(v.stock)||999, i]);
      }
    }
    res.json(fmtProduct(rows[0]));
  } catch (e) { console.error(e); res.status(500).json({ error: 'DB error' }); }
});

app.delete('/api/products/:id', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM products WHERE id=$1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    if (rows[0].image) { const p = path.join(__dirname, rows[0].image); if (fs.existsSync(p)) fs.unlinkSync(p); }
    await pool.query('DELETE FROM products WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

// ── COUPONS ────────────────────────────────────────────────────
app.post('/api/coupons/validate', async (req, res) => {
  const { code, price } = req.body;
  if (!code) return res.status(400).json({ error: 'Code required' });
  try {
    const { rows } = await pool.query('SELECT * FROM coupons WHERE UPPER(code)=UPPER($1) AND active=true', [code]);
    if (!rows.length) return res.status(404).json({ error: 'Invalid or expired coupon' });
    const c = rows[0];
    if (c.max_uses > 0 && c.uses >= c.max_uses) return res.status(400).json({ error: 'Coupon max uses reached' });
    if (c.expires_at && new Date(c.expires_at) < new Date()) return res.status(400).json({ error: 'Coupon has expired' });
    const discount = parseFloat(price) * (parseFloat(c.discount_percent) / 100);
    res.json({ valid: true, code: c.code, discount_percent: parseFloat(c.discount_percent), discount_amount: discount, final_price: parseFloat(price) - discount });
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.get('/api/coupons', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM coupons ORDER BY created_at DESC');
    res.json(rows);
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.post('/api/coupons', requireAdmin, async (req, res) => {
  const { code, discount_percent, max_uses, expires_at } = req.body;
  if (!code || !discount_percent) return res.status(400).json({ error: 'Code and discount required' });
  try {
    const { rows } = await pool.query(`INSERT INTO coupons (code,discount_percent,max_uses,expires_at) VALUES (UPPER($1),$2,$3,$4) RETURNING *`,
      [code, parseFloat(discount_percent), parseInt(max_uses)||0, expires_at||null]);
    res.status(201).json(rows[0]);
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Code already exists' });
    res.status(500).json({ error: 'DB error' });
  }
});

app.delete('/api/coupons/:id', requireAdmin, async (req, res) => {
  try { await pool.query('DELETE FROM coupons WHERE id=$1', [req.params.id]); res.json({ success: true }); }
  catch (e) { res.status(500).json({ error: 'DB error' }); }
});

// ── ANNOUNCEMENTS ──────────────────────────────────────────────
app.get('/api/announcements', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM announcements WHERE active=true ORDER BY created_at DESC LIMIT 1');
    res.json(rows[0] || null);
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.post('/api/announcements', requireAdmin, async (req, res) => {
  const { message, color } = req.body;
  if (!message) return res.status(400).json({ error: 'Message required' });
  try {
    await pool.query('UPDATE announcements SET active=false');
    const { rows } = await pool.query(`INSERT INTO announcements (message,color) VALUES ($1,$2) RETURNING *`, [message, color||'yellow']);
    res.status(201).json(rows[0]);
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.delete('/api/announcements', requireAdmin, async (req, res) => {
  try { await pool.query('UPDATE announcements SET active=false'); res.json({ success: true }); }
  catch (e) { res.status(500).json({ error: 'DB error' }); }
});

// ── WAITLIST ───────────────────────────────────────────────────
app.post('/api/waitlist', async (req, res) => {
  const { product_id, product_name, discord_username } = req.body;
  if (!product_name || !discord_username) return res.status(400).json({ error: 'Required fields missing' });
  try {
    await pool.query(`INSERT INTO waitlist (product_id,product_name,discord_username) VALUES ($1,$2,$3)`, [product_id||null, product_name, discord_username]);
    res.status(201).json({ success: true });
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.get('/api/waitlist', requireAdmin, async (req, res) => {
  try { const { rows } = await pool.query('SELECT * FROM waitlist ORDER BY created_at DESC'); res.json(rows); }
  catch (e) { res.status(500).json({ error: 'DB error' }); }
});

// ── INQUIRIES ──────────────────────────────────────────────────
app.post('/api/inquiries', async (req, res) => {
  const { product_id, product_name, product_price, variant_name, discord_username, discord_id, coupon_code, discount_amount, final_price, note } = req.body;
  if (!product_name) return res.status(400).json({ error: 'product_name required' });
  try {
    // Increment coupon uses
    if (coupon_code) await pool.query('UPDATE coupons SET uses = uses + 1 WHERE UPPER(code)=UPPER($1)', [coupon_code]);

    const { rows } = await pool.query(`INSERT INTO inquiries (product_id,product_name,product_price,variant_name,discord_username,discord_id,coupon_code,discount_amount,final_price,note) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [product_id||null, product_name, parseFloat(product_price||0), variant_name||null, discord_username||'Unknown', discord_id||null, coupon_code||null, parseFloat(discount_amount||0), parseFloat(final_price||product_price||0), note||null]);

    const fields = [
      { name: '📦 Product', value: product_name + (variant_name ? ` — ${variant_name}` : ''), inline: true },
      { name: '💰 Price', value: `$${parseFloat(final_price||product_price||0).toFixed(2)}`, inline: true },
      { name: '👤 Discord', value: discord_username || 'Unknown', inline: true }
    ];
    if (coupon_code) fields.push({ name: '🎟️ Coupon', value: `${coupon_code} (-$${parseFloat(discount_amount||0).toFixed(2)})`, inline: true });
    await sendDiscordEmbed(INQUIRY_CHANNEL, [{ title: '🛒 New Purchase Inquiry', color: 0xe8c547, fields, footer: { text: `ID: ${rows[0].id} • No Man's Land` }, timestamp: new Date().toISOString() }]);

    if (product_id) {
      const { rows: prod } = await pool.query('SELECT * FROM products WHERE id=$1', [product_id]);
      if (prod.length && prod[0].stock <= 5 && prod[0].stock > 0) {
        await sendDiscordEmbed(ADMIN_CHANNEL, [{ title: '⚠️ Low Stock Alert', color: 0xff4040, fields: [{ name: 'Product', value: prod[0].name, inline: true }, { name: 'Stock Left', value: String(prod[0].stock), inline: true }], timestamp: new Date().toISOString() }]);
      }
    }
    res.status(201).json({ success: true, id: rows[0].id });
  } catch (e) { console.error(e); res.status(500).json({ error: 'DB error' }); }
});

app.get('/api/inquiries', requireAdmin, async (req, res) => {
  try { const { rows } = await pool.query('SELECT * FROM inquiries ORDER BY created_at DESC LIMIT 200'); res.json(rows); }
  catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.patch('/api/inquiries/:id', requireAdmin, async (req, res) => {
  const { status } = req.body;
  try {
    const { rows } = await pool.query('UPDATE inquiries SET status=$1 WHERE id=$2 RETURNING *', [status, req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

// ── STATS ──────────────────────────────────────────────────────
app.get('/api/stats', requireAdmin, async (req, res) => {
  try {
    const [totalRev, weekOrders, topProduct, totalOrders, totalProducts] = await Promise.all([
      pool.query(`SELECT COALESCE(SUM(final_price),0) as total FROM inquiries WHERE status != 'cancelled'`),
      pool.query(`SELECT COUNT(*) as count FROM inquiries WHERE created_at > NOW() - INTERVAL '7 days'`),
      pool.query(`SELECT product_name, COUNT(*) as count FROM inquiries GROUP BY product_name ORDER BY count DESC LIMIT 1`),
      pool.query(`SELECT COUNT(*) as count FROM inquiries`),
      pool.query(`SELECT COUNT(*) as count FROM products WHERE coming_soon=false`)
    ]);
    res.json({
      total_revenue: parseFloat(totalRev.rows[0].total).toFixed(2),
      orders_this_week: parseInt(weekOrders.rows[0].count),
      top_product: topProduct.rows[0]?.product_name || 'N/A',
      total_orders: parseInt(totalOrders.rows[0].count),
      total_products: parseInt(totalProducts.rows[0].count)
    });
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

// ── BOT ENDPOINTS ──────────────────────────────────────────────
app.get('/api/bot/stock', async (req, res) => {
  try { const { rows } = await pool.query('SELECT name, stock, coming_soon FROM products ORDER BY name ASC'); res.json(rows); }
  catch (e) { res.status(500).json({ error: 'DB error' }); }
});

function botAuth(req, res, next) {
  if (req.body.secret !== BOT_SECRET) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

app.post('/api/bot/setstock', (req, res, next) => { req.body = req.body || {}; next(); }, botAuth, async (req, res) => {
  const { product_name, stock } = req.body;
  try {
    const { rows } = await pool.query(`UPDATE products SET stock=$1 WHERE LOWER(name) LIKE LOWER($2) RETURNING name, stock`, [parseInt(stock), `%${product_name}%`]);
    if (!rows.length) return res.status(404).json({ error: 'Product not found' });
    res.json({ updated: rows });
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.post('/api/bot/setstockall', botAuth, async (req, res) => {
  try { await pool.query('UPDATE products SET stock=$1 WHERE coming_soon=false', [parseInt(req.body.stock)]); res.json({ success: true }); }
  catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.post('/api/bot/announce', botAuth, async (req, res) => {
  try {
    await pool.query('UPDATE announcements SET active=false');
    await pool.query(`INSERT INTO announcements (message,color) VALUES ($1,$2)`, [req.body.message, req.body.color||'yellow']);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.post('/api/bot/clearannounce', botAuth, async (req, res) => {
  try { await pool.query('UPDATE announcements SET active=false'); res.json({ success: true }); }
  catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.post('/api/bot/coupon', botAuth, async (req, res) => {
  const { code, discount_percent, max_uses, expires_at } = req.body;
  try {
    const { rows } = await pool.query(`INSERT INTO coupons (code,discount_percent,max_uses,expires_at) VALUES (UPPER($1),$2,$3,$4) RETURNING *`,
      [code, parseFloat(discount_percent), parseInt(max_uses)||0, expires_at||null]);
    res.status(201).json(rows[0]);
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Code already exists' });
    res.status(500).json({ error: 'DB error' });
  }
});

app.post('/api/bot/givetheme', botAuth, async (req, res) => {
  const { discord_id, theme } = req.body;
  try {
    const { rows } = await pool.query(`UPDATE users SET owned_themes = array_append(array_remove(owned_themes,$1),$1), updated_at=NOW() WHERE id=$2 RETURNING *`, [theme, discord_id]);
    if (!rows.length) return res.status(404).json({ error: 'User not found — must log in to store first' });
    res.json({ success: true, owned_themes: rows[0].owned_themes });
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.post('/api/bot/revoketheme', botAuth, async (req, res) => {
  const { discord_id, theme } = req.body;
  try {
    const { rows } = await pool.query(`UPDATE users SET owned_themes = array_remove(owned_themes,$1), updated_at=NOW() WHERE id=$2 RETURNING *`, [theme, discord_id]);
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true, owned_themes: rows[0].owned_themes });
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.post('/api/bot/membership', botAuth, async (req, res) => {
  const { discord_id, action } = req.body;
  try {
    const { rows } = await pool.query(`UPDATE users SET is_member=$1, updated_at=NOW() WHERE id=$2 RETURNING *`, [action==='give', discord_id]);
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true, is_member: rows[0].is_member });
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.get('/api/bot/stats', async (req, res) => {
  try {
    const [rev, week, top] = await Promise.all([
      pool.query(`SELECT COALESCE(SUM(final_price),0) as total FROM inquiries WHERE status != 'cancelled'`),
      pool.query(`SELECT COUNT(*) as count FROM inquiries WHERE created_at > NOW() - INTERVAL '7 days'`),
      pool.query(`SELECT product_name, COUNT(*) as count FROM inquiries GROUP BY product_name ORDER BY count DESC LIMIT 3`)
    ]);
    res.json({ total_revenue: parseFloat(rev.rows[0].total).toFixed(2), orders_this_week: parseInt(week.rows[0].count), top_products: top.rows });
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

// ── CATCH ALL ──────────────────────────────────────────────────
app.get('*', (req, res) => {
  const p = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(p)) res.sendFile(p);
  else res.json({ message: "No Man's Land API running." });
});

// ── BOOT ───────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log(`\n🔫 No Man's Land v3 — Port ${PORT}\n`));
  startBot();
}).catch(err => { console.error('DB init failed:', err); process.exit(1); });

// ══════════════════════════════════════════════════════════════
// DISCORD BOT
// ══════════════════════════════════════════════════════════════
function startBot() {
  if (!BOT_TOKEN) { console.log('[Bot] No token, skipping'); return; }
  const { Client, GatewayIntentBits, EmbedBuilder } = require('discord.js');

  const client = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent, GatewayIntentBits.DirectMessages] });
  client.once('ready', () => console.log(`[Bot] ${client.user.tag} ready`));

  client.on('messageCreate', async (msg) => {
    if (msg.author.bot || msg.channelId !== ADMIN_CHANNEL || !msg.content.startsWith('!')) return;
    const args = msg.content.slice(1).trim().split(/\s+/);
    const cmd = args.shift().toLowerCase();
    const isOwner = msg.author.id === OWNER_ID;

    const botPost = async (endpoint, body={}) => {
      const r = await fetch(`${STORE_URL}/api/bot/${endpoint}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ secret: BOT_SECRET, ...body }) });
      return { ok: r.ok, data: await r.json() };
    };

    // !stock
    if (cmd === 'stock') {
      const r = await fetch(`${STORE_URL}/api/bot/stock`);
      const products = await r.json();
      const lines = products.map(p => p.coming_soon ? `⏳ **${p.name}** — Coming Soon` : `${p.stock > 50 ? '🟢' : p.stock > 10 ? '🟡' : p.stock > 0 ? '🔴' : '⛔'} **${p.name}** — ${p.stock}`);
      msg.reply({ embeds: [new EmbedBuilder().setTitle('🔫 Stock Levels').setColor(0xe8c547).setDescription(lines.join('\n')).setTimestamp()] });
    }

    // !setstock <name> <amount>
    else if (cmd === 'setstock') {
      const amount = parseInt(args.pop());
      const name = args.join(' ');
      if (!name || isNaN(amount)) return msg.reply('Usage: `!setstock <product name> <amount>`');
      const { ok, data } = await botPost('setstock', { product_name: name, stock: amount });
      if (!ok) return msg.reply(`❌ ${data.error}`);
      msg.reply(data.updated.map(p => `✅ **${p.name}** → ${p.stock}`).join('\n'));
    }

    // !setstockall <amount>
    else if (cmd === 'setstockall') {
      const amount = parseInt(args[0]);
      if (isNaN(amount)) return msg.reply('Usage: `!setstockall <amount>`');
      await botPost('setstockall', { stock: amount });
      msg.reply(`✅ All products set to **${amount}** stock.`);
    }

    // !orders
    else if (cmd === 'orders') {
      const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '1m' });
      const r = await fetch(`${STORE_URL}/api/inquiries`, { headers: { 'Authorization': `Bearer ${token}` } });
      const inquiries = await r.json();
      const recent = inquiries.slice(0, 10);
      if (!recent.length) return msg.reply('No orders yet.');
      const lines = recent.map(inq => `${inq.status === 'done' ? '✅' : inq.status === 'cancelled' ? '❌' : '⏳'} **${inq.product_name}** — ${inq.discord_username} — $${parseFloat(inq.final_price||0).toFixed(2)}`);
      msg.reply({ embeds: [new EmbedBuilder().setTitle('🛒 Last 10 Orders').setColor(0xe8c547).setDescription(lines.join('\n')).setTimestamp()] });
    }

    // !stats
    else if (cmd === 'stats') {
      const r = await fetch(`${STORE_URL}/api/bot/stats`);
      const s = await r.json();
      const embed = new EmbedBuilder().setTitle('📊 Store Stats').setColor(0xe8c547)
        .addFields(
          { name: '💰 Total Revenue', value: `$${s.total_revenue}`, inline: true },
          { name: '📦 Orders This Week', value: String(s.orders_this_week), inline: true },
          { name: '🔥 Top Products', value: s.top_products.map(p => `**${p.product_name}** (${p.count})`).join('\n') || 'N/A', inline: false }
        ).setTimestamp();
      msg.reply({ embeds: [embed] });
    }

    // !search <query>
    else if (cmd === 'search') {
      const query = args.join(' ');
      if (!query) return msg.reply('Usage: `!search <product name>`');
      const r = await fetch(`${STORE_URL}/api/products?search=${encodeURIComponent(query)}`);
      const products = await r.json();
      if (!products.length) return msg.reply(`No products found for "${query}"`);
      const lines = products.slice(0, 8).map(p => `**${p.name}** — $${p.price} — ${p.stock > 0 ? p.stock + ' in stock' : 'Out of Stock'}`);
      msg.reply({ embeds: [new EmbedBuilder().setTitle(`🔍 Search: "${query}"`).setColor(0xe8c547).setDescription(lines.join('\n'))] });
    }

    // !coupon create <code> <percent> [expires: YYYY-MM-DD] [max: N]
    else if (cmd === 'coupon') {
      const sub = args.shift()?.toLowerCase();
      if (sub === 'create') {
        const code = args[0], percent = parseFloat(args[1]);
        let expires_at = null, max_uses = 0;
        args.slice(2).forEach(a => {
          if (a.startsWith('expires:')) expires_at = a.split(':')[1];
          if (a.startsWith('max:')) max_uses = parseInt(a.split(':')[1]);
        });
        if (!code || isNaN(percent)) return msg.reply('Usage: `!coupon create <CODE> <percent> [expires:YYYY-MM-DD] [max:N]`');
        const { ok, data } = await botPost('coupon', { code, discount_percent: percent, max_uses, expires_at });
        if (!ok) return msg.reply(`❌ ${data.error}`);
        msg.reply(`✅ Coupon **${data.code}** — **${percent}%** off${expires_at ? ` · expires ${expires_at}` : ''}${max_uses ? ` · max ${max_uses} uses` : ''}`);
      } else {
        msg.reply('Usage: `!coupon create <CODE> <percent> [expires:YYYY-MM-DD] [max:N]`');
      }
    }

    // !announce <message>
    else if (cmd === 'announce') {
      const message = args.join(' ');
      if (!message) return msg.reply('Usage: `!announce <message>`');
      await botPost('announce', { message });
      msg.reply(`✅ Banner posted: "${message}"`);
    }

    // !clearannounce
    else if (cmd === 'clearannounce') {
      await botPost('clearannounce');
      msg.reply('✅ Announcement banner cleared.');
    }

    // !givetheme <discord_id> <theme>
    else if (cmd === 'givetheme') {
      const [discord_id, theme] = args;
      if (!discord_id || !theme) return msg.reply('Usage: `!givetheme <discord_id> <theme>`\nThemes: red, yellow, blue, green, white, orange, pink, rainbow, blackwhite, black');
      const { ok, data } = await botPost('givetheme', { discord_id, theme });
      if (!ok) return msg.reply(`❌ ${data.error}`);
      msg.reply(`✅ Gave **${theme}** theme to <@${discord_id}>`);
    }

    // !revoketheme <discord_id> <theme>
    else if (cmd === 'revoketheme') {
      const [discord_id, theme] = args;
      if (!discord_id || !theme) return msg.reply('Usage: `!revoketheme <discord_id> <theme>`');
      const { ok, data } = await botPost('revoketheme', { discord_id, theme });
      if (!ok) return msg.reply(`❌ ${data.error}`);
      msg.reply(`✅ Revoked **${theme}** theme from <@${discord_id}>`);
    }

    // !membership give/revoke <discord_id> — OWNER ONLY
    else if (cmd === 'membership') {
      if (!isOwner) return msg.reply('❌ Only the store owner can manage memberships.');
      const [action, discord_id] = args;
      if (!action || !discord_id) return msg.reply('Usage: `!membership give <discord_id>` or `!membership revoke <discord_id>`');
      const { ok, data } = await botPost('membership', { discord_id, action });
      if (!ok) return msg.reply(`❌ ${data.error}`);
      msg.reply(`✅ Membership **${action === 'give' ? 'granted' : 'revoked'}** for <@${discord_id}>`);
    }

    // !addproduct
    else if (cmd === 'addproduct') {
      const parts = args.join(' ').split('|').map(s => s.trim());
      if (parts.length < 3) return msg.reply(
        '**Usage:** `!addproduct <name> | <price> | <category> | <badge> | <stock> | <description>`\nAttach an image.\n**Example:** `!addproduct Netflix 4K | 0.50 | Accounts | HOT | 50 | Full 4K access`'
      );
      const [pName, pPrice, pCategory, pBadge, pStock, ...descParts] = parts;
      try {
        let imagePath = null;
        const attachment = msg.attachments.first();
        if (attachment) {
          const imgRes = await fetch(attachment.url);
          const buffer = await imgRes.buffer();
          const filename = `${uuidv4()}${path.extname(attachment.name)||'.png'}`;
          imagePath = `/uploads/${filename}`;
          fs.writeFileSync(path.join(uploadsDir, filename), buffer);
        }
        const { rows } = await pool.query(`INSERT INTO products (name,description,price,category,image,badge,stock,featured,coming_soon) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
          [pName, descParts.join('|')||'', parseFloat(pPrice)||0, pCategory||'Accounts', imagePath, pBadge&&pBadge!=='-'?pBadge.toUpperCase():null, parseInt(pStock)||999, false, false]);
        msg.reply({ embeds: [new EmbedBuilder().setTitle('✅ Product Created!').setColor(0xe8c547)
          .addFields({ name: 'Name', value: rows[0].name, inline: true }, { name: 'Price', value: `$${rows[0].price}`, inline: true }, { name: 'Stock', value: String(rows[0].stock), inline: true })
          .setThumbnail(imagePath ? `${STORE_URL}${imagePath}` : null)] });
      } catch (e) { msg.reply('❌ ' + e.message); }
    }

    // !help
    else if (cmd === 'help') {
      msg.reply({ embeds: [new EmbedBuilder().setTitle('🔫 No Man\'s Land Bot').setColor(0xe8c547).setDescription(
        '`!stock` — Stock levels\n`!setstock <n> <amt>` — Set product stock\n`!setstockall <amt>` — Set all stock\n`!orders` — Last 10 orders\n`!stats` — Revenue & top products\n`!search <query>` — Search products\n`!coupon create <CODE> <pct> [expires:DATE] [max:N]` — Create coupon\n`!announce <msg>` — Post store banner\n`!clearannounce` — Remove banner\n`!givetheme <id> <theme>` — Give theme to user\n`!revoketheme <id> <theme>` — Revoke theme\n`!membership give/revoke <id>` — Manage membership *(owner only)*\n`!addproduct <n>|<price>|<cat>|<badge>|<stock>|<desc>` — Add product\n`!help` — This message'
      )] });
    }
  });

  client.login(BOT_TOKEN).catch(e => console.error('[Bot] Login failed:', e.message));
}
