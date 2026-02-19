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

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nml-secret-change-me';
const ADMIN_PASSWORD_HASH = bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 10);
const INQUIRY_CHANNEL_ID = '1472992778173812756';
const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;

// ── PostgreSQL ─────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.PG_URL || process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ── DB INIT ────────────────────────────────────────────────────────────────────
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS products (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name TEXT NOT NULL,
        description TEXT DEFAULT '',
        price NUMERIC(10,2) NOT NULL DEFAULT 0,
        original_price NUMERIC(10,2),
        category TEXT DEFAULT 'Accounts',
        image TEXT,
        badge TEXT,
        stock INTEGER DEFAULT 999,
        featured BOOLEAN DEFAULT false,
        coming_soon BOOLEAN DEFAULT false,
        views INTEGER DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS product_variants (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        product_id UUID REFERENCES products(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        price NUMERIC(10,2) NOT NULL,
        original_price NUMERIC(10,2),
        stock INTEGER DEFAULT 999,
        sort_order INTEGER DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS inquiries (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        product_id UUID,
        product_name TEXT NOT NULL,
        product_price NUMERIC(10,2) DEFAULT 0,
        variant_name TEXT,
        discord_username TEXT DEFAULT 'Unknown',
        discord_id TEXT,
        coupon_code TEXT,
        discount_amount NUMERIC(10,2) DEFAULT 0,
        final_price NUMERIC(10,2) DEFAULT 0,
        note TEXT,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS coupons (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        code TEXT UNIQUE NOT NULL,
        discount_percent NUMERIC(5,2) NOT NULL,
        max_uses INTEGER DEFAULT 0,
        uses INTEGER DEFAULT 0,
        active BOOLEAN DEFAULT true,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS announcements (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        message TEXT NOT NULL,
        active BOOLEAN DEFAULT true,
        color TEXT DEFAULT 'yellow',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS waitlist (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        product_id UUID,
        product_name TEXT NOT NULL,
        discord_username TEXT NOT NULL,
        notified BOOLEAN DEFAULT false,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // Add new columns to existing products table if upgrading
    const cols = ['original_price NUMERIC(10,2)', 'views INTEGER DEFAULT 0'];
    for (const col of cols) {
      const colName = col.split(' ')[0];
      await client.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS ${col}`).catch(() => {});
    }
    await client.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS original_price NUMERIC(10,2)`).catch(() => {});
    await client.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS views INTEGER DEFAULT 0`).catch(() => {});

    const { rows } = await client.query('SELECT COUNT(*) FROM products');
    if (parseInt(rows[0].count) === 0) {
      await seedProducts(client);
    }
    console.log('✅ Database ready');
  } finally {
    client.release();
  }
}

async function seedProducts(client) {
  const products = [
    { id: '12f92f56-34b7-4a8a-b0f5-45e9ca8dbcc5', name: 'Amazon Prime Video Premium', description: '- Full Access to AMZ Prime Video Premium!\n- Lifetime subscription, $0 fees!\n- 12 Months (reoccurring)\n- Checked accounts! User and Pass\n- Email, Phone, etc. and Pass CAN be changed!\n- NO RESELLING!\n\nWe do NOT replace any issues. All accounts are checked and NOT verified so you can verify and change the email and password yourself. If any issues happen, dm on Discord and we\'ll try to resolve it. If we can\'t sorry!', price: 1.10, category: 'Accounts', image: '/uploads/b15c251d-45ed-48a7-9028-281de7f19ed9.png', badge: null, stock: 93, featured: true },
    { id: 'a6e11dd5-a2c9-433c-abc2-78ba8b036a63', name: 'Spotify Premium', description: '- Full Access to Spotify Premium\n- Lifetime subscription, $0 fees!\n- 12 Months (reoccurring)\n- Checked accounts! User and Pass\n- Email, Phone, etc. and Pass CAN be changed!\n- NO RESELLING!\n\nWe do NOT replace any issues. All accounts are checked and NOT verified so you can verify and change the email and password yourself.', price: 1.80, category: 'Accounts', image: '/uploads/cd444c5a-aa87-45cb-8759-32e7adfbb916.png', badge: 'HOT', stock: 87, featured: true },
    { id: '28998b63-669d-44da-867c-1e30432740c6', name: 'Crunchyroll Premium', description: '- Full Access to CR Premium\n- Lifetime subscription, $0 fees!\n- 12 Months (reoccurring)\n- Checked accounts! User and Pass\n- NO RESELLING!', price: 0.12, category: 'Accounts', image: '/uploads/de1540a1-0563-4f7d-af2d-3759d3f32d26.png', badge: null, stock: 100, featured: true },
    { id: '2d6df3ec-274d-46d1-8255-78f3c4b27307', name: 'Netflix Premium', description: '- Full Access to Netflix Premium\n- Lifetime subscription, $0 fees!\n- 12 Months (reoccurring)\n- Checked accounts! User and Pass\n- Email, Phone, etc. and Pass CAN be changed!\n- NO RESELLING!', price: 0.25, category: 'Accounts', image: '/uploads/9e1dc7bc-f84e-43ed-9c2f-5a31ce4ff850.png', badge: 'NEW', stock: 100, featured: true },
    { id: '4a9b3bbb-6ece-4c2a-809e-0c1dd3d88c7b', name: '14x Server Boosts (1 MONTH)', description: '- Full Access to 14x Server Boosts for 1 Month!\n- 1 month subscription!\n- NOT reoccurring\n- NO RESELLING!', price: 2.25, category: 'Other', image: '/uploads/51b23eb3-e0a4-4908-9f0d-400ddaebb161.png', badge: 'HOT', stock: 999, featured: true },
    { id: '0d8ea7ca-d99c-4ac7-9070-b91b92690eaa', name: '1K Discord Server Members', description: 'Coming soon!', price: 0, category: 'Software', image: '/uploads/48fb0798-85af-43bf-9b53-9c26550537bb.png', badge: 'SOON', stock: 0, featured: false, coming_soon: true },
    { id: 'f504a483-c37c-4204-aa89-3c5d8d066f9e', name: 'HBO Max Premium', description: '- Full Access to HBO Max Premium\n- 12 Months (reoccurring)\n- NO RESELLING!', price: 0.33, category: 'Accounts', image: '/uploads/4464bb4a-16f1-464e-81a7-69b56615f0d7.png', badge: 'NEW', stock: 121 },
    { id: '4bf8b2bc-461e-4028-bbd3-de0cbf7abc75', name: 'Steam Premium', description: '- Full Access to STEAM Premium\n- 12 Months (reoccurring)\n- NO RESELLING!', price: 0.19, category: 'Accounts', image: '/uploads/63caa547-d6e7-4d0f-85f1-12f0ce59ee78.png', badge: 'SALE', stock: 78 },
    { id: '50d7ad68-11d1-4206-b1b5-680167f36fe6', name: 'CapCut Premium', description: '- Full Access to CapCut Premium (PRO)\n- 12 Months (reoccurring)\n- NO RESELLING!', price: 0.32, category: 'Accounts', image: '/uploads/3a818cd3-077a-4fb3-b14d-c636a1af341a.png', badge: null, stock: 62 },
    { id: '7867c87f-9340-4001-9108-c26a2460ba55', name: 'Paramount+ Premium', description: '- Full Access to Paramount+ Premium\n- 12 Months (reoccurring)\n- NO RESELLING!', price: 0.12, category: 'Accounts', image: '/uploads/fccd9b4a-479b-491c-aff0-24ae6931c833.png', badge: 'NEW', stock: 150 },
    { id: '3953e1f0-8311-4c8b-b043-b3119e889dae', name: 'YouTube Premium', description: '- Full Access to YT Premium\n- 12 Months (reoccurring)\n- NO RESELLING!', price: 0.35, category: 'Accounts', image: '/uploads/31a07239-74c0-43d7-85cc-f213d1ec861c.png', badge: 'SALE', stock: 100 }
  ];
  for (const p of products) {
    await client.query(`
      INSERT INTO products (id,name,description,price,category,image,badge,stock,featured,coming_soon)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (id) DO NOTHING
    `, [p.id, p.name, p.description, p.price, p.category, p.image, p.badge||null, p.stock||999, p.featured||false, p.coming_soon||false]);
  }
  console.log('✅ Seeded 11 products');
}

// ── Middleware ─────────────────────────────────────────────────────────────────
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
// ROUTES
// ══════════════════════════════════════════════════════════════

app.get('/api/health', (req, res) => res.json({ status: 'online', store: "No Man's Land" }));

// ── AUTH ───────────────────────────────────────────────────────
app.post('/api/admin/login', async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });
  const valid = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
  if (!valid) return res.status(401).json({ error: 'Wrong password' });
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token });
});

// ── PRODUCTS ───────────────────────────────────────────────────
app.get('/api/products', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM products ORDER BY featured DESC, created_at DESC');
    // Attach variants
    const { rows: variants } = await pool.query('SELECT * FROM product_variants ORDER BY sort_order ASC');
    const result = rows.map(p => ({
      ...fmtProduct(p),
      variants: variants.filter(v => v.product_id === p.id).map(v => ({
        id: v.id, name: v.name, price: parseFloat(v.price),
        original_price: v.original_price ? parseFloat(v.original_price) : null,
        stock: v.stock, sort_order: v.sort_order
      }))
    }));
    res.json(result);
  } catch (e) { console.error(e); res.status(500).json({ error: 'DB error' }); }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM products WHERE id=$1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    // Track view
    await pool.query('UPDATE products SET views = COALESCE(views,0) + 1 WHERE id=$1', [req.params.id]);
    const { rows: variants } = await pool.query('SELECT * FROM product_variants WHERE product_id=$1 ORDER BY sort_order ASC', [req.params.id]);
    res.json({
      ...fmtProduct(rows[0]),
      variants: variants.map(v => ({ id: v.id, name: v.name, price: parseFloat(v.price), original_price: v.original_price ? parseFloat(v.original_price) : null, stock: v.stock, sort_order: v.sort_order }))
    });
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.post('/api/products', requireAdmin, upload.single('image'), async (req, res) => {
  const { name, description, price, original_price, category, badge, stock, featured, coming_soon, variants } = req.body;
  if (!name || price === undefined) return res.status(400).json({ error: 'Name and price required' });
  try {
    const { rows } = await pool.query(`
      INSERT INTO products (name,description,price,original_price,category,image,badge,stock,featured,coming_soon)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *
    `, [name, description||'', parseFloat(price), original_price ? parseFloat(original_price) : null,
        category||'Accounts', req.file ? `/uploads/${req.file.filename}` : null,
        badge||null, parseInt(stock)||999, featured==='true', coming_soon==='true']);
    const product = rows[0];
    // Save variants
    if (variants) {
      const parsed = typeof variants === 'string' ? JSON.parse(variants) : variants;
      for (let i = 0; i < parsed.length; i++) {
        const v = parsed[i];
        await pool.query(`INSERT INTO product_variants (product_id,name,price,original_price,stock,sort_order) VALUES ($1,$2,$3,$4,$5,$6)`,
          [product.id, v.name, parseFloat(v.price), v.original_price ? parseFloat(v.original_price) : null, parseInt(v.stock)||999, i]);
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
    const { rows } = await pool.query(`
      UPDATE products SET name=$1,description=$2,price=$3,original_price=$4,category=$5,image=$6,badge=$7,stock=$8,featured=$9,coming_soon=$10,updated_at=NOW()
      WHERE id=$11 RETURNING *
    `, [name??old.name, description!==undefined?description:old.description,
        price!==undefined?parseFloat(price):old.price,
        original_price!==undefined?(original_price?parseFloat(original_price):null):old.original_price,
        category??old.category, req.file?`/uploads/${req.file.filename}`:old.image,
        badge!==undefined?(badge||null):old.badge,
        stock!==undefined?parseInt(stock):old.stock,
        featured!==undefined?featured==='true':old.featured,
        coming_soon!==undefined?coming_soon==='true':old.coming_soon,
        req.params.id]);
    // Replace variants
    if (variants !== undefined) {
      await pool.query('DELETE FROM product_variants WHERE product_id=$1', [req.params.id]);
      const parsed = typeof variants === 'string' ? JSON.parse(variants) : variants;
      for (let i = 0; i < parsed.length; i++) {
        const v = parsed[i];
        await pool.query(`INSERT INTO product_variants (product_id,name,price,original_price,stock,sort_order) VALUES ($1,$2,$3,$4,$5,$6)`,
          [req.params.id, v.name, parseFloat(v.price), v.original_price?parseFloat(v.original_price):null, parseInt(v.stock)||999, i]);
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
    if (c.max_uses > 0 && c.uses >= c.max_uses) return res.status(400).json({ error: 'Coupon has reached max uses' });
    const discount = parseFloat(price) * (parseFloat(c.discount_percent) / 100);
    const final = parseFloat(price) - discount;
    res.json({ valid: true, code: c.code, discount_percent: parseFloat(c.discount_percent), discount_amount: discount, final_price: final });
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.get('/api/coupons', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM coupons ORDER BY created_at DESC');
    res.json(rows);
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.post('/api/coupons', requireAdmin, async (req, res) => {
  const { code, discount_percent, max_uses } = req.body;
  if (!code || !discount_percent) return res.status(400).json({ error: 'Code and discount required' });
  try {
    const { rows } = await pool.query(`INSERT INTO coupons (code,discount_percent,max_uses) VALUES (UPPER($1),$2,$3) RETURNING *`,
      [code, parseFloat(discount_percent), parseInt(max_uses)||0]);
    res.status(201).json(rows[0]);
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Coupon code already exists' });
    res.status(500).json({ error: 'DB error' });
  }
});

app.delete('/api/coupons/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM coupons WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
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
  try {
    await pool.query('UPDATE announcements SET active=false');
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

// ── WAITLIST ───────────────────────────────────────────────────
app.post('/api/waitlist', async (req, res) => {
  const { product_id, product_name, discord_username } = req.body;
  if (!product_name || !discord_username) return res.status(400).json({ error: 'product_name and discord_username required' });
  try {
    const { rows } = await pool.query(`INSERT INTO waitlist (product_id,product_name,discord_username) VALUES ($1,$2,$3) RETURNING *`,
      [product_id||null, product_name, discord_username]);
    res.status(201).json({ success: true });
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.get('/api/waitlist', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM waitlist ORDER BY created_at DESC');
    res.json(rows);
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

// ── INQUIRIES ──────────────────────────────────────────────────
app.post('/api/inquiries', async (req, res) => {
  const { product_id, product_name, product_price, variant_name, discord_username, coupon_code, discount_amount, final_price, note } = req.body;
  if (!product_name) return res.status(400).json({ error: 'product_name required' });
  try {
    const { rows } = await pool.query(`
      INSERT INTO inquiries (product_id,product_name,product_price,variant_name,discord_username,coupon_code,discount_amount,final_price,note)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *
    `, [product_id||null, product_name, parseFloat(product_price||0), variant_name||null,
        discord_username||'Unknown', coupon_code||null, parseFloat(discount_amount||0), parseFloat(final_price||product_price||0), note||null]);

    // Notify Discord
    const fields = [
      { name: '📦 Product', value: product_name + (variant_name ? ` — ${variant_name}` : ''), inline: true },
      { name: '💰 Price', value: `$${parseFloat(final_price||product_price||0).toFixed(2)}`, inline: true },
      { name: '👤 Discord', value: discord_username || 'Not provided', inline: true },
    ];
    if (coupon_code) fields.push({ name: '🎟️ Coupon', value: `${coupon_code} (-${discount_amount})`, inline: true });
    await sendDiscordEmbed(INQUIRY_CHANNEL_ID, [{ title: '🛒 New Purchase Inquiry', color: 0xe8c547, fields, footer: { text: `ID: ${rows[0].id} • No Man's Land` }, timestamp: new Date().toISOString() }]);

    // Check low stock and notify
    if (product_id) {
      const { rows: prod } = await pool.query('SELECT * FROM products WHERE id=$1', [product_id]);
      if (prod.length && prod[0].stock <= 5 && prod[0].stock > 0) {
        await sendDiscordEmbed('1472988444220461240', [{ title: '⚠️ Low Stock Alert', color: 0xff4040, fields: [{ name: 'Product', value: prod[0].name, inline: true }, { name: 'Stock Left', value: String(prod[0].stock), inline: true }], timestamp: new Date().toISOString() }]);
      }
    }

    res.status(201).json({ success: true, id: rows[0].id });
  } catch (e) { console.error(e); res.status(500).json({ error: 'DB error' }); }
});

app.get('/api/inquiries', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM inquiries ORDER BY created_at DESC LIMIT 200');
    res.json(rows);
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.patch('/api/inquiries/:id', requireAdmin, async (req, res) => {
  const { status } = req.body;
  try {
    const { rows } = await pool.query('UPDATE inquiries SET status=$1 WHERE id=$2 RETURNING *', [status, req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

// ── INTERNAL: Bot endpoints ────────────────────────────────────
// These are called by the Discord bot to interact with the store
app.get('/api/bot/stock', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT name, stock, coming_soon FROM products ORDER BY name ASC');
    res.json(rows);
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.post('/api/bot/setstock', async (req, res) => {
  const { secret, product_name, stock } = req.body;
  if (secret !== (process.env.BOT_SECRET || 'nml-bot-secret')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const { rows } = await pool.query(`UPDATE products SET stock=$1 WHERE LOWER(name) LIKE LOWER($2) RETURNING name, stock`, [`${stock}`, `%${product_name}%`]);
    if (!rows.length) return res.status(404).json({ error: 'Product not found' });
    res.json({ updated: rows });
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.post('/api/bot/setstockall', async (req, res) => {
  const { secret, stock } = req.body;
  if (secret !== (process.env.BOT_SECRET || 'nml-bot-secret')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    await pool.query('UPDATE products SET stock=$1 WHERE coming_soon=false', [parseInt(stock)]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.post('/api/bot/announce', async (req, res) => {
  const { secret, message, color } = req.body;
  if (secret !== (process.env.BOT_SECRET || 'nml-bot-secret')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    await pool.query('UPDATE announcements SET active=false');
    await pool.query(`INSERT INTO announcements (message,color) VALUES ($1,$2)`, [message, color||'yellow']);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

app.post('/api/bot/coupon', async (req, res) => {
  const { secret, code, discount_percent, max_uses } = req.body;
  if (secret !== (process.env.BOT_SECRET || 'nml-bot-secret')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const { rows } = await pool.query(`INSERT INTO coupons (code,discount_percent,max_uses) VALUES (UPPER($1),$2,$3) RETURNING *`,
      [code, parseFloat(discount_percent), parseInt(max_uses)||0]);
    res.status(201).json(rows[0]);
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Code already exists' });
    res.status(500).json({ error: 'DB error' });
  }
});

// ── CATCH ALL ──────────────────────────────────────────────────
app.get('*', (req, res) => {
  const p = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(p)) res.sendFile(p);
  else res.json({ message: "No Man's Land API running." });
});

// ── BOOT ───────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log(`\n🔫 No Man's Land v2 — Port ${PORT}\n`));
  // Start Discord bot
  startBot();
}).catch(err => { console.error('DB init failed:', err); process.exit(1); });

// ══════════════════════════════════════════════════════════════
// DISCORD BOT
// ══════════════════════════════════════════════════════════════
function startBot() {
  if (!BOT_TOKEN) { console.log('[Bot] No token set, skipping'); return; }

  const { Client, GatewayIntentBits, EmbedBuilder, AttachmentBuilder } = require('discord.js');
  const ADMIN_CHANNEL = '1472988444220461240';
  const BOT_SECRET = process.env.BOT_SECRET || 'nml-bot-secret';
  const STORE_URL = process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : `http://localhost:${PORT}`;

  const client = new Client({
    intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent, GatewayIntentBits.DirectMessages]
  });

  client.once('ready', () => console.log(`[Bot] Logged in as ${client.user.tag}`));

  client.on('messageCreate', async (msg) => {
    if (msg.author.bot) return;
    if (msg.channelId !== ADMIN_CHANNEL) return;
    if (!msg.content.startsWith('!')) return;

    const args = msg.content.slice(1).trim().split(/\s+/);
    const cmd = args.shift().toLowerCase();

    // ── !stock ──────────────────────────────────────────────────
    if (cmd === 'stock') {
      try {
        const res = await fetch(`${STORE_URL}/api/bot/stock`);
        const products = await res.json();
        const embed = new EmbedBuilder()
          .setTitle('🔫 No Man\'s Land — Stock Levels')
          .setColor(0xe8c547)
          .setTimestamp();
        const lines = products.map(p => {
          if (p.coming_soon) return `⏳ **${p.name}** — Coming Soon`;
          const bar = p.stock > 50 ? '🟢' : p.stock > 10 ? '🟡' : p.stock > 0 ? '🔴' : '⛔';
          return `${bar} **${p.name}** — ${p.stock} in stock`;
        });
        embed.setDescription(lines.join('\n'));
        msg.reply({ embeds: [embed] });
      } catch (e) { msg.reply('❌ Failed to fetch stock.'); }
    }

    // ── !setstock <name> <amount> ───────────────────────────────
    else if (cmd === 'setstock') {
      const amount = parseInt(args.pop());
      const name = args.join(' ');
      if (!name || isNaN(amount)) return msg.reply('Usage: `!setstock <product name> <amount>`');
      try {
        const res = await fetch(`${STORE_URL}/api/bot/setstock`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ secret: BOT_SECRET, product_name: name, stock: amount })
        });
        const data = await res.json();
        if (!res.ok) return msg.reply(`❌ ${data.error}`);
        const lines = data.updated.map(p => `✅ **${p.name}** → ${p.stock} stock`).join('\n');
        msg.reply(lines);
      } catch (e) { msg.reply('❌ Server error.'); }
    }

    // ── !setstockall <amount> ────────────────────────────────────
    else if (cmd === 'setstockall') {
      const amount = parseInt(args[0]);
      if (isNaN(amount)) return msg.reply('Usage: `!setstockall <amount>`');
      try {
        await fetch(`${STORE_URL}/api/bot/setstockall`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ secret: BOT_SECRET, stock: amount })
        });
        msg.reply(`✅ All products set to **${amount}** stock.`);
      } catch (e) { msg.reply('❌ Server error.'); }
    }

    // ── !orders ──────────────────────────────────────────────────
    else if (cmd === 'orders') {
      try {
        const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '1m' });
        const res = await fetch(`${STORE_URL}/api/inquiries`, { headers: { 'Authorization': `Bearer ${token}` } });
        const inquiries = await res.json();
        const recent = inquiries.slice(0, 10);
        if (!recent.length) return msg.reply('No orders yet.');
        const embed = new EmbedBuilder()
          .setTitle('🛒 Last 10 Orders')
          .setColor(0xe8c547)
          .setTimestamp();
        const lines = recent.map((inq, i) => {
          const date = new Date(inq.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
          const status = inq.status === 'done' ? '✅' : inq.status === 'cancelled' ? '❌' : '⏳';
          return `${status} **${inq.product_name}** — ${inq.discord_username} — $${parseFloat(inq.final_price||0).toFixed(2)} — ${date}`;
        });
        embed.setDescription(lines.join('\n'));
        msg.reply({ embeds: [embed] });
      } catch (e) { msg.reply('❌ Failed to fetch orders.'); }
    }

    // ── !coupon create <code> <percent> [maxuses] ────────────────
    else if (cmd === 'coupon') {
      const sub = args.shift()?.toLowerCase();
      if (sub === 'create') {
        const code = args[0];
        const percent = parseFloat(args[1]);
        const maxUses = parseInt(args[2]) || 0;
        if (!code || isNaN(percent)) return msg.reply('Usage: `!coupon create <CODE> <percent> [max_uses]`');
        try {
          const res = await fetch(`${STORE_URL}/api/bot/coupon`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ secret: BOT_SECRET, code, discount_percent: percent, max_uses: maxUses })
          });
          const data = await res.json();
          if (!res.ok) return msg.reply(`❌ ${data.error}`);
          msg.reply(`✅ Coupon **${data.code}** created — **${percent}%** off${maxUses ? ` (max ${maxUses} uses)` : ' (unlimited)'}`);
        } catch (e) { msg.reply('❌ Server error.'); }
      } else {
        msg.reply('Usage: `!coupon create <CODE> <percent> [max_uses]`');
      }
    }

    // ── !announce <message> ──────────────────────────────────────
    else if (cmd === 'announce') {
      const message = args.join(' ');
      if (!message) return msg.reply('Usage: `!announce <your message here>`');
      try {
        await fetch(`${STORE_URL}/api/bot/announce`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ secret: BOT_SECRET, message })
        });
        msg.reply(`✅ Announcement posted to the store: "${message}"`);
      } catch (e) { msg.reply('❌ Server error.'); }
    }

    // ── !addproduct ──────────────────────────────────────────────
    else if (cmd === 'addproduct') {
      // Multi-step: !addproduct starts a flow
      // Usage: !addproduct <name> | <price> | <category> | <badge> | <stock> | <description>
      // Attach image to the message
      const parts = args.join(' ').split('|').map(s => s.trim());
      if (parts.length < 3) {
        return msg.reply(
          '**Usage:** `!addproduct <name> | <price> | <category> | <badge> | <stock> | <description>`\n' +
          'Attach an image to the message.\n' +
          '**Categories:** Accounts, Digital, Software, Gaming, Other\n' +
          '**Badges:** NEW, HOT, SALE, LIMITED, SOON (or leave empty)\n' +
          '**Example:** `!addproduct Netflix Premium | 0.25 | Accounts | NEW | 100 | Full access Netflix account`'
        );
      }
      const [pName, pPrice, pCategory, pBadge, pStock, ...descParts] = parts;
      const pDesc = descParts.join('|');
      const attachment = msg.attachments.first();

      try {
        // Download image if attached
        let imagePath = null;
        if (attachment) {
          const imgRes = await fetch(attachment.url);
          const buffer = await imgRes.buffer();
          const ext = path.extname(attachment.name) || '.png';
          const filename = `${uuidv4()}${ext}`;
          imagePath = `/uploads/${filename}`;
          fs.writeFileSync(path.join(uploadsDir, filename), buffer);
        }

        const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '1m' });
        const body = {
          name: pName, price: parseFloat(pPrice) || 0,
          category: pCategory || 'Accounts',
          badge: pBadge && pBadge !== '-' ? pBadge.toUpperCase() : '',
          stock: parseInt(pStock) || 999,
          description: pDesc || '',
          featured: 'false', coming_soon: 'false'
        };

        // If image was downloaded, we need to use internal DB directly
        const { rows } = await pool.query(`
          INSERT INTO products (name,description,price,category,image,badge,stock,featured,coming_soon)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *
        `, [body.name, body.description, body.price, body.category, imagePath, body.badge||null, body.stock, false, false]);

        const embed = new EmbedBuilder()
          .setTitle('✅ Product Created!')
          .setColor(0xe8c547)
          .addFields(
            { name: 'Name', value: rows[0].name, inline: true },
            { name: 'Price', value: `$${rows[0].price}`, inline: true },
            { name: 'Category', value: rows[0].category, inline: true },
            { name: 'Badge', value: rows[0].badge || 'None', inline: true },
            { name: 'Stock', value: String(rows[0].stock), inline: true },
          );
        if (imagePath) embed.setThumbnail(`${STORE_URL}${imagePath}`);
        msg.reply({ embeds: [embed] });
      } catch (e) { console.error(e); msg.reply('❌ Failed to create product: ' + e.message); }
    }

    // ── !help ────────────────────────────────────────────────────
    else if (cmd === 'help') {
      const embed = new EmbedBuilder()
        .setTitle('🔫 No Man\'s Land Bot Commands')
        .setColor(0xe8c547)
        .setDescription(
          '`!stock` — View all stock levels\n' +
          '`!setstock <name> <amount>` — Set stock for a product\n' +
          '`!setstockall <amount>` — Set all products to same stock\n' +
          '`!orders` — View last 10 orders\n' +
          '`!coupon create <CODE> <percent> [max_uses]` — Create discount coupon\n' +
          '`!announce <message>` — Post announcement to store\n' +
          '`!addproduct <name> | <price> | <category> | <badge> | <stock> | <desc>` — Add product (attach image)\n' +
          '`!help` — Show this message'
        );
      msg.reply({ embeds: [embed] });
    }
  });

  client.login(BOT_TOKEN).catch(e => console.error('[Bot] Login failed:', e.message));
}
