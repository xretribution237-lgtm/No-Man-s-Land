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
const JWT_SECRET = process.env.JWT_SECRET || 'nml-super-secret-key-change-in-prod';
const ADMIN_PASSWORD_HASH = bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 10);
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN || null;
const INQUIRY_CHANNEL_ID = '1472992778173812756';

// ── PostgreSQL ─────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// ── DB Init ────────────────────────────────────────────────────────────────────
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS products (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name TEXT NOT NULL,
        description TEXT DEFAULT '',
        price NUMERIC(10,2) NOT NULL DEFAULT 0,
        category TEXT DEFAULT 'Digital',
        image TEXT,
        badge TEXT,
        stock INTEGER DEFAULT 999,
        featured BOOLEAN DEFAULT false,
        coming_soon BOOLEAN DEFAULT false,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS inquiries (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        product_id UUID,
        product_name TEXT NOT NULL,
        product_price NUMERIC(10,2) DEFAULT 0,
        discord_username TEXT DEFAULT 'Unknown',
        discord_id TEXT,
        note TEXT,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    const { rows } = await client.query('SELECT COUNT(*) FROM products');
    if (parseInt(rows[0].count) === 0) {
      console.log('Seeding 11 existing products...');
      await seedProducts(client);
    }

    console.log('✅ Database ready');
  } finally {
    client.release();
  }
}

async function seedProducts(client) {
  const products = [
    {
      id: '12f92f56-34b7-4a8a-b0f5-45e9ca8dbcc5',
      name: 'Amazon Prime Video Premium',
      description: '- Full Access to AMZ Prime Video Premium!\n- Lifetime subscription, $0 fees!\n- 12 Months (reoccurring)\n- Checked accounts! User and Pass\n- Email, Phone, etc. and Pass CAN be changed!\n- NO RESELLING!\n\nWe do NOT replace any issues. All accounts are checked and NOT verified so you can verify and change the email and password yourself. If any issues happen, dm on Discord and we\'ll try to resolve it. If we can\'t sorry!',
      price: 1.10, category: 'Accounts', image: '/uploads/b15c251d-45ed-48a7-9028-281de7f19ed9.png',
      badge: null, stock: 93, featured: true, coming_soon: false
    },
    {
      id: 'a6e11dd5-a2c9-433c-abc2-78ba8b036a63',
      name: 'Spotify Premium',
      description: '- Full Access to Spotify Premium\n- Lifetime subscription, $0 fees!\n- 12 Months (reoccurring)\n- Checked accounts! User and Pass\n- Email, Phone, etc. and Pass CAN be changed!\n- NO RESELLING!\n\nWe do NOT replace any issues. All accounts are checked and NOT verified so you can verify and change the email and password yourself. If any issues happen, dm on Discord and we\'ll try to resolve it. If we can\'t sorry!',
      price: 1.80, category: 'Accounts', image: '/uploads/cd444c5a-aa87-45cb-8759-32e7adfbb916.png',
      badge: 'HOT', stock: 87, featured: true, coming_soon: false
    },
    {
      id: '28998b63-669d-44da-867c-1e30432740c6',
      name: 'Crunchyroll Premium',
      description: '- Full Access to CR Premium\n- Lifetime subscription, $0 fees!\n- 12 Months (reoccurring)\n- Checked accounts! User and Pass\n- Email, Phone, etc. and Pass CAN be changed!\n- NO RESELLING!\n\nWe do NOT replace any issues. All accounts are checked and NOT verified so you can verify and change the email and password yourself. If any issues happen, dm on Discord and we\'ll try to resolve it. If we can\'t sorry!',
      price: 0.12, category: 'Accounts', image: '/uploads/de1540a1-0563-4f7d-af2d-3759d3f32d26.png',
      badge: null, stock: 100, featured: true, coming_soon: false
    },
    {
      id: '2d6df3ec-274d-46d1-8255-78f3c4b27307',
      name: 'Netflix Premium',
      description: '- Full Access to Netflix Premium\n- Lifetime subscription, $0 fees!\n- 12 Months (reoccurring)\n- Checked accounts! User and Pass\n- Email, Phone, etc. and Pass CAN be changed!\n- NO RESELLING!\n\nWe do NOT replace any issues. All accounts are checked and NOT verified so you can verify and change the email and password yourself. If any issues happen, dm on Discord and we\'ll try to resolve it. If we can\'t sorry!',
      price: 0.25, category: 'Accounts', image: '/uploads/9e1dc7bc-f84e-43ed-9c2f-5a31ce4ff850.png',
      badge: 'NEW', stock: 100, featured: true, coming_soon: false
    },
    {
      id: '4a9b3bbb-6ece-4c2a-809e-0c1dd3d88c7b',
      name: '14x Server Boosts (1 MONTH)',
      description: '- Full Access to 14x Server Boosts for 1 Month!\n- 1 month subscription!\n- 1 Month (NOT reoccurring)\n- Checked accounts! User and Pass\n- Email, Phone, etc. can be used for payout!\n- NO RESELLING!\n\nWe do NOT replace any issues. All accounts are checked and NOT verified so you can verify and change the email and password yourself. If any issues happen, dm on Discord and we\'ll try to resolve it. If we can\'t sorry!',
      price: 2.25, category: 'Other', image: '/uploads/51b23eb3-e0a4-4908-9f0d-400ddaebb161.png',
      badge: 'HOT', stock: 999, featured: true, coming_soon: false
    },
    {
      id: '0d8ea7ca-d99c-4ac7-9070-b91b92690eaa',
      name: '1K Discord Server Members (OFFLINE or ONLINE)',
      description: 'Coming soon!',
      price: 0, category: 'Software', image: '/uploads/48fb0798-85af-43bf-9b53-9c26550537bb.png',
      badge: 'SOON', stock: 0, featured: false, coming_soon: true
    },
    {
      id: 'f504a483-c37c-4204-aa89-3c5d8d066f9e',
      name: 'HBO Max Premium',
      description: '- Full Access to HBO Max Premium\n- Lifetime subscription, $0 fees!\n- 12 Months (reoccurring)\n- Checked accounts! User and Pass\n- Email, Phone, etc. and Pass CAN be changed!\n- NO RESELLING!\n\nWe do NOT replace any issues. All accounts are checked and NOT verified so you can verify and change the email and password yourself. If any issues happen, dm on Discord and we\'ll try to resolve it. If we can\'t sorry!',
      price: 0.33, category: 'Accounts', image: '/uploads/4464bb4a-16f1-464e-81a7-69b56615f0d7.png',
      badge: 'NEW', stock: 121, featured: false, coming_soon: false
    },
    {
      id: '4bf8b2bc-461e-4028-bbd3-de0cbf7abc75',
      name: 'Steam Premium',
      description: '- Full Access to STEAM Premium\n- Lifetime subscription, $0 fees!\n- 12 Months (reoccurring)\n- Checked accounts! User and Pass\n- Email, Phone, etc. and Pass CAN be changed!\n- NO RESELLING!\n\nWe do NOT replace any issues. All accounts are checked and NOT verified so you can verify and change the email and password yourself. If any issues happen, dm on Discord and we\'ll try to resolve it. If we can\'t sorry!',
      price: 0.19, category: 'Accounts', image: '/uploads/63caa547-d6e7-4d0f-85f1-12f0ce59ee78.png',
      badge: 'SALE', stock: 78, featured: false, coming_soon: false
    },
    {
      id: '50d7ad68-11d1-4206-b1b5-680167f36fe6',
      name: 'CapCut Premium',
      description: '- Full Access to CapCut Premium (PRO)\n- Lifetime subscription, $0 fees!\n- 12 Months (reoccurring)\n- Checked accounts! User and Pass\n- Email, Phone, etc. and Pass CAN be changed!\n- NO RESELLING!\n\nWe do NOT replace any issues. All accounts are checked and NOT verified so you can verify and change the email and password yourself. If any issues happen, dm on Discord and we\'ll try to resolve it. If we can\'t sorry!',
      price: 0.32, category: 'Accounts', image: '/uploads/3a818cd3-077a-4fb3-b14d-c636a1af341a.png',
      badge: null, stock: 62, featured: false, coming_soon: false
    },
    {
      id: '7867c87f-9340-4001-9108-c26a2460ba55',
      name: 'Paramount+ Premium',
      description: '- Full Access to Paramount+ Premium\n- Lifetime subscription, $0 fees!\n- 12 Months (reoccurring)\n- Checked accounts! User and Pass\n- Email, Phone, etc. and Pass CAN be changed!\n- NO RESELLING!\n\nWe do NOT replace any issues. All accounts are checked and NOT verified so you can verify and change the email and password yourself. If any issues happen, dm on Discord and we\'ll try to resolve it. If we can\'t sorry!',
      price: 0.12, category: 'Accounts', image: '/uploads/fccd9b4a-479b-491c-aff0-24ae6931c833.png',
      badge: 'NEW', stock: 150, featured: false, coming_soon: false
    },
    {
      id: '3953e1f0-8311-4c8b-b043-b3119e889dae',
      name: 'YouTube Premium',
      description: '- Full Access to YT Premium\n- Lifetime subscription, $0 fees!\n- 12 Months (reoccurring)\n- Checked accounts! User and Pass\n- Email, Phone, etc. and Pass CAN be changed!\n- NO RESELLING!\n\nWe do NOT replace any issues. All accounts are checked and NOT verified so you can verify and change the email and password yourself. If any issues happen, dm on Discord and we\'ll try to resolve it. If we can\'t sorry!',
      price: 0.35, category: 'Accounts', image: '/uploads/31a07239-74c0-43d7-85cc-f213d1ec861c.png',
      badge: 'SALE', stock: 100, featured: false, coming_soon: false
    }
  ];

  for (const p of products) {
    await client.query(`
      INSERT INTO products (id, name, description, price, category, image, badge, stock, featured, coming_soon)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
      ON CONFLICT (id) DO NOTHING
    `, [p.id, p.name, p.description, p.price, p.category, p.image, p.badge, p.stock, p.featured, p.coming_soon]);
  }
  console.log(`✅ Seeded ${products.length} products`);
}

// ── Middleware ─────────────────────────────────────────────────────────────────
app.use(cors({ origin: process.env.FRONTEND_URL || '*', credentials: true }));
app.use(express.json());

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
app.use('/uploads', express.static(uploadsDir));
app.use(express.static(path.join(__dirname, 'public')));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname)}`)
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(null, /jpeg|jpg|png|gif|webp/.test(file.mimetype))
});

function requireAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(auth.split(' ')[1], JWT_SECRET);
    if (decoded.role !== 'admin') throw new Error();
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

async function sendDiscordMessage(channelId, embeds) {
  if (!DISCORD_BOT_TOKEN) return;
  try {
    await fetch(`https://discord.com/api/v10/channels/${channelId}/messages`, {
      method: 'POST',
      headers: { 'Authorization': `Bot ${DISCORD_BOT_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ embeds })
    });
  } catch (e) { console.error('[Discord]', e.message); }
}

function formatProduct(row) {
  return {
    id: row.id, name: row.name, description: row.description,
    price: parseFloat(row.price), category: row.category,
    image: row.image, badge: row.badge, stock: row.stock,
    featured: row.featured, coming_soon: row.coming_soon,
    createdAt: row.created_at, updatedAt: row.updated_at
  };
}

// ── PRODUCT ROUTES ─────────────────────────────────────────────────────────────

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
    const { rows } = await pool.query('SELECT * FROM products ORDER BY created_at DESC');
    res.json(rows.map(formatProduct));
  } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM products WHERE id=$1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(formatProduct(rows[0]));
  } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

app.post('/api/products', requireAdmin, upload.single('image'), async (req, res) => {
  const { name, description, price, category, badge, stock, featured, coming_soon } = req.body;
  if (!name || price === undefined) return res.status(400).json({ error: 'Name and price required' });
  try {
    const { rows } = await pool.query(`
      INSERT INTO products (name, description, price, category, image, badge, stock, featured, coming_soon)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *
    `, [name, description || '', parseFloat(price), category || 'Digital',
        req.file ? `/uploads/${req.file.filename}` : null,
        badge || null, parseInt(stock) || 999,
        featured === 'true', coming_soon === 'true']);
    res.status(201).json(formatProduct(rows[0]));
  } catch (e) { console.error(e); res.status(500).json({ error: 'Database error' }); }
});

app.put('/api/products/:id', requireAdmin, upload.single('image'), async (req, res) => {
  try {
    const { rows: ex } = await pool.query('SELECT * FROM products WHERE id=$1', [req.params.id]);
    if (!ex.length) return res.status(404).json({ error: 'Not found' });
    const old = ex[0];
    if (req.file && old.image) { const p = path.join(__dirname, old.image); if (fs.existsSync(p)) fs.unlinkSync(p); }
    const { name, description, price, category, badge, stock, featured, coming_soon } = req.body;
    const { rows } = await pool.query(`
      UPDATE products SET name=$1,description=$2,price=$3,category=$4,image=$5,badge=$6,stock=$7,featured=$8,coming_soon=$9,updated_at=NOW()
      WHERE id=$10 RETURNING *
    `, [name??old.name, description!==undefined?description:old.description,
        price!==undefined?parseFloat(price):old.price, category??old.category,
        req.file?`/uploads/${req.file.filename}`:old.image,
        badge!==undefined?(badge||null):old.badge,
        stock!==undefined?parseInt(stock):old.stock,
        featured!==undefined?featured==='true':old.featured,
        coming_soon!==undefined?coming_soon==='true':old.coming_soon,
        req.params.id]);
    res.json(formatProduct(rows[0]));
  } catch (e) { console.error(e); res.status(500).json({ error: 'Database error' }); }
});

app.delete('/api/products/:id', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM products WHERE id=$1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    if (rows[0].image) { const p = path.join(__dirname, rows[0].image); if (fs.existsSync(p)) fs.unlinkSync(p); }
    await pool.query('DELETE FROM products WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

// ── INQUIRY ROUTES ─────────────────────────────────────────────────────────────

app.post('/api/inquiries', async (req, res) => {
  const { product_id, product_name, product_price, discord_username, discord_id, note } = req.body;
  if (!product_name) return res.status(400).json({ error: 'product_name required' });
  try {
    const { rows } = await pool.query(`
      INSERT INTO inquiries (product_id, product_name, product_price, discord_username, discord_id, note)
      VALUES ($1,$2,$3,$4,$5,$6) RETURNING *
    `, [product_id||null, product_name, parseFloat(product_price||0),
        discord_username||'Unknown', discord_id||null, note||null]);

    // Notify Discord ticket channel
    await sendDiscordMessage(INQUIRY_CHANNEL_ID, [{
      title: '🛒 New Purchase Inquiry',
      color: 0xe8c547,
      fields: [
        { name: '📦 Product', value: product_name, inline: true },
        { name: '💰 Price', value: `$${parseFloat(product_price||0).toFixed(2)}`, inline: true },
        { name: '👤 Discord User', value: discord_username || 'Not provided', inline: true },
        { name: '🆔 Discord ID', value: discord_id || 'Not provided', inline: true },
        { name: '📝 Note', value: note || '—', inline: false }
      ],
      footer: { text: `ID: ${rows[0].id} • No Man's Land Store` },
      timestamp: new Date().toISOString()
    }]);

    res.status(201).json({ success: true, id: rows[0].id });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Database error' }); }
});

app.get('/api/inquiries', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM inquiries ORDER BY created_at DESC LIMIT 200');
    res.json(rows);
  } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

app.patch('/api/inquiries/:id', requireAdmin, async (req, res) => {
  const { status } = req.body;
  try {
    const { rows } = await pool.query('UPDATE inquiries SET status=$1 WHERE id=$2 RETURNING *', [status, req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

// ── CATCH ALL ──────────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  const p = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(p)) res.sendFile(p);
  else res.json({ message: "No Man's Land API running." });
});

// ── BOOT ───────────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`\n🔫 No Man's Land — Port ${PORT}`);
    console.log(`   http://localhost:${PORT}/api/health\n`);
  });
}).catch(err => { console.error('DB init failed:', err); process.exit(1); });
