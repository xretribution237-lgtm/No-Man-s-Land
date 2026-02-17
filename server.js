require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nml-super-secret-key-change-in-prod';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 10);
const DISCORD_WEBHOOK = process.env.DISCORD_WEBHOOK || 'https://discord.com/api/webhooks/1473408834142863537/0IHEhHm8AClH1hokKw1NlGxKHXVF0RAMIsOMVLFdcEDs1EfGkyZru2V_IGtd6SnFy74Y';

app.use(cors({ origin: process.env.FRONTEND_URL || '*', credentials: true }));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname)}`)
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 }, fileFilter: (req, file, cb) => cb(null, /jpeg|jpg|png|gif|webp/.test(file.mimetype)) });

const DATA_FILE = path.join(__dirname, 'data.json');

function loadData() {
  if (!fs.existsSync(DATA_FILE)) {
    const d = { products: [], coupons: [], orders: [], reviews: [] };
    fs.writeFileSync(DATA_FILE, JSON.stringify(d, null, 2));
    return d;
  }
  const data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  if (!data.coupons) data.coupons = [];
  if (!data.orders) data.orders = [];
  if (!data.reviews) data.reviews = [];
  return data;
}

function saveData(data) { fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2)); }

function requireAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(auth.split(' ')[1], JWT_SECRET);
    if (decoded.role !== 'admin') throw new Error();
    next();
  } catch { res.status(401).json({ error: 'Invalid or expired token' }); }
}

async function sendWebhook(payload) {
  if (!DISCORD_WEBHOOK) return;
  try {
    const body = JSON.stringify(payload);
    const url = new URL(DISCORD_WEBHOOK);
    return new Promise((resolve) => {
      const req = https.request({
        hostname: url.hostname, path: url.pathname + url.search,
        method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
      }, (res) => { resolve(res.statusCode); });
      req.on('error', () => resolve(null));
      req.write(body); req.end();
    });
  } catch (e) { console.error('Webhook error:', e.message); }
}

// ── ROUTES ────────────────────────────────────────────────────────────────────

app.get('/api/health', (req, res) => res.json({ status: 'online', store: "No Man's Land" }));

app.post('/api/admin/login', async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });
  const valid = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
  if (!valid) return res.status(401).json({ error: 'Wrong password' });
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token });
});

// PRODUCTS
app.get('/api/products', (req, res) => {
  const data = loadData();
  let isAdmin = false;
  try {
    const auth = req.headers.authorization;
    if (auth?.startsWith('Bearer ')) {
      const d = jwt.verify(auth.split(' ')[1], JWT_SECRET);
      isAdmin = d.role === 'admin';
    }
  } catch {}
  let products = data.products;
  if (!isAdmin) {
    products = products.map(p => p.coming_soon
      ? { id: p.id, name: p.name, coming_soon: true, category: p.category, badge: 'SOON', image: p.image, featured: p.featured }
      : p);
  }
  res.json(products);
});

app.post('/api/products', requireAdmin, upload.single('image'), async (req, res) => {
  const { name, description, price, category, badge, stock, featured, coming_soon } = req.body;
  if (!name || !price) return res.status(400).json({ error: 'Name and price required' });
  const data = loadData();
  const product = {
    id: uuidv4(), name, description: description || '',
    price: parseFloat(price), category: category || 'Digital',
    image: req.file ? `/uploads/${req.file.filename}` : null,
    badge: badge || null, stock: parseInt(stock) || 999,
    featured: featured === 'true', coming_soon: coming_soon === 'true',
    createdAt: new Date().toISOString()
  };
  if (product.featured) { data.products.unshift(product); }
  else {
    const lastFeat = data.products.reduce((acc, p, i) => p.featured ? i : acc, -1);
    data.products.splice(lastFeat + 1, 0, product);
  }
  saveData(data);
  if (!product.coming_soon) {
    sendWebhook({ embeds: [{ title: '🔫 New Product Listed!', color: 0xe8c547,
      fields: [
        { name: '📦 Product', value: product.name, inline: true },
        { name: '💰 Price', value: `$${product.price.toFixed(2)}`, inline: true },
        { name: '🏷️ Category', value: product.category, inline: true },
        { name: '📊 Stock', value: product.stock >= 999 ? 'Unlimited' : `${product.stock} units`, inline: true },
        ...(product.badge ? [{ name: '🔖 Badge', value: product.badge, inline: true }] : []),
        ...(product.description ? [{ name: '📝 Description', value: product.description.substring(0, 200) }] : []),
      ],
      footer: { text: "No Man's Land Store" }, timestamp: new Date().toISOString()
    }]});
  }
  res.status(201).json(product);
});

app.put('/api/products/:id', requireAdmin, upload.single('image'), async (req, res) => {
  const data = loadData();
  const idx = data.products.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const { name, description, price, category, badge, stock, featured, coming_soon } = req.body;
  const existing = data.products[idx];
  if (req.file && existing.image) { const op = path.join(__dirname, existing.image); if (fs.existsSync(op)) fs.unlinkSync(op); }
  data.products[idx] = {
    ...existing,
    name: name || existing.name,
    description: description !== undefined ? description : existing.description,
    price: price !== undefined ? parseFloat(price) : existing.price,
    category: category || existing.category,
    badge: badge !== undefined ? badge : existing.badge,
    stock: stock !== undefined ? parseInt(stock) : existing.stock,
    featured: featured !== undefined ? featured === 'true' : existing.featured,
    coming_soon: coming_soon !== undefined ? coming_soon === 'true' : existing.coming_soon,
    image: req.file ? `/uploads/${req.file.filename}` : existing.image,
    updatedAt: new Date().toISOString()
  };
  saveData(data);
  sendWebhook({ embeds: [{ title: '✏️ Product Updated', color: 0x00b8d4,
    fields: [
      { name: '📦 Product', value: data.products[idx].name, inline: true },
      { name: '💰 Price', value: `$${data.products[idx].price.toFixed(2)}`, inline: true },
    ],
    footer: { text: "No Man's Land Store" }, timestamp: new Date().toISOString()
  }]});
  res.json(data.products[idx]);
});

app.delete('/api/products/:id', requireAdmin, (req, res) => {
  const data = loadData();
  const idx = data.products.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const product = data.products[idx];
  if (product.image) { const ip = path.join(__dirname, product.image); if (fs.existsSync(ip)) fs.unlinkSync(ip); }
  data.products.splice(idx, 1);
  saveData(data);
  res.json({ success: true });
});

app.post('/api/products/:id/purchase', (req, res) => {
  const data = loadData();
  const product = data.products.find(p => p.id === req.params.id);
  if (!product) return res.status(404).json({ error: 'Not found' });
  if (product.stock < 999 && product.stock > 0) { product.stock--; saveData(data); }
  res.json({ stock: product.stock });
});

// COUPONS
app.get('/api/coupons', requireAdmin, (req, res) => res.json(loadData().coupons));

app.post('/api/coupons/validate', (req, res) => {
  const { code, price } = req.body;
  const data = loadData();
  const coupon = data.coupons.find(c => c.code.toUpperCase() === code.toUpperCase() && c.active);
  if (!coupon) return res.status(404).json({ error: 'Invalid or expired coupon' });
  if (coupon.uses >= coupon.maxUses) return res.status(400).json({ error: 'Coupon fully used' });
  const original = parseFloat(price);
  const discount = coupon.type === 'percent' ? (original * coupon.value / 100) : coupon.value;
  const final = Math.max(0, original - discount).toFixed(2);
  res.json({ valid: true, coupon, original, discount: discount.toFixed(2), final });
});

app.post('/api/coupons', requireAdmin, (req, res) => {
  const { code, type, value, maxUses } = req.body;
  if (!code || !type || !value) return res.status(400).json({ error: 'Missing fields' });
  const data = loadData();
  if (data.coupons.find(c => c.code.toUpperCase() === code.toUpperCase())) return res.status(400).json({ error: 'Code already exists' });
  const coupon = { id: uuidv4(), code: code.toUpperCase(), type, value: parseFloat(value), maxUses: parseInt(maxUses) || 999, uses: 0, active: true, createdAt: new Date().toISOString() };
  data.coupons.push(coupon);
  saveData(data);
  res.status(201).json(coupon);
});

app.put('/api/coupons/:id', requireAdmin, (req, res) => {
  const data = loadData();
  const idx = data.coupons.findIndex(c => c.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  data.coupons[idx] = { ...data.coupons[idx], ...req.body };
  saveData(data);
  res.json(data.coupons[idx]);
});

app.delete('/api/coupons/:id', requireAdmin, (req, res) => {
  const data = loadData();
  data.coupons = data.coupons.filter(c => c.id !== req.params.id);
  saveData(data);
  res.json({ success: true });
});

// ORDERS
app.get('/api/orders', requireAdmin, (req, res) => res.json(loadData().orders.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))));

app.post('/api/orders', async (req, res) => {
  const { productId, discordUsername, note, couponCode, finalPrice } = req.body;
  if (!productId || !discordUsername) return res.status(400).json({ error: 'Missing fields' });
  const data = loadData();
  const product = data.products.find(p => p.id === productId);
  if (!product) return res.status(404).json({ error: 'Product not found' });
  if (product.coming_soon) return res.status(400).json({ error: 'Product not available yet' });
  if (couponCode) {
    const coupon = data.coupons.find(c => c.code.toUpperCase() === couponCode.toUpperCase() && c.active);
    if (coupon) coupon.uses++;
  }
  const order = { id: uuidv4(), productId, productName: product.name, productPrice: product.price, finalPrice: finalPrice || product.price, couponCode: couponCode || null, discordUsername, note: note || '', status: 'pending', createdAt: new Date().toISOString() };
  data.orders.push(order);
  saveData(data);
  sendWebhook({ embeds: [{ title: '🛒 New Order Inquiry!', color: 0xff4040,
    fields: [
      { name: '📦 Product', value: product.name, inline: true },
      { name: '💰 Price', value: `$${parseFloat(order.finalPrice).toFixed(2)}`, inline: true },
      { name: '👤 Discord', value: discordUsername, inline: true },
      ...(couponCode ? [{ name: '🎟️ Coupon', value: couponCode, inline: true }] : []),
      ...(note ? [{ name: '📝 Note', value: note }] : []),
    ],
    footer: { text: "No Man's Land Store" }, timestamp: new Date().toISOString()
  }]});
  res.status(201).json(order);
});

app.put('/api/orders/:id/status', requireAdmin, (req, res) => {
  const data = loadData();
  const order = data.orders.find(o => o.id === req.params.id);
  if (!order) return res.status(404).json({ error: 'Not found' });
  order.status = req.body.status;
  saveData(data);
  res.json(order);
});

// REVIEWS
app.get('/api/reviews', (req, res) => {
  const { productId } = req.query;
  const data = loadData();
  const reviews = productId ? data.reviews.filter(r => r.productId === productId && r.approved) : data.reviews;
  res.json(reviews);
});

app.post('/api/reviews', (req, res) => {
  const { productId, discordUsername, rating, comment } = req.body;
  if (!productId || !discordUsername || !rating) return res.status(400).json({ error: 'Missing fields' });
  const data = loadData();
  const product = data.products.find(p => p.id === productId);
  if (!product) return res.status(404).json({ error: 'Product not found' });
  const review = { id: uuidv4(), productId, productName: product.name, discordUsername, rating: Math.min(5, Math.max(1, parseInt(rating))), comment: comment || '', approved: false, createdAt: new Date().toISOString() };
  data.reviews.push(review);
  saveData(data);
  sendWebhook({ embeds: [{ title: '⭐ New Review (Pending)', color: 0xffcc00,
    fields: [
      { name: '📦 Product', value: product.name, inline: true },
      { name: '⭐ Rating', value: `${'★'.repeat(review.rating)}${'☆'.repeat(5 - review.rating)}`, inline: true },
      { name: '👤 User', value: discordUsername, inline: true },
      ...(comment ? [{ name: '💬 Comment', value: comment }] : []),
    ],
    footer: { text: "Approve in Admin Panel" }, timestamp: new Date().toISOString()
  }]});
  res.status(201).json({ success: true, message: 'Review submitted, pending approval' });
});

app.put('/api/reviews/:id/approve', requireAdmin, (req, res) => {
  const data = loadData();
  const review = data.reviews.find(r => r.id === req.params.id);
  if (!review) return res.status(404).json({ error: 'Not found' });
  review.approved = req.body.approved !== false;
  saveData(data);
  res.json(review);
});

app.delete('/api/reviews/:id', requireAdmin, (req, res) => {
  const data = loadData();
  data.reviews = data.reviews.filter(r => r.id !== req.params.id);
  saveData(data);
  res.json({ success: true });
});

app.get('*', (req, res) => {
  const indexPath = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(indexPath)) res.sendFile(indexPath);
  else res.json({ message: "No Man's Land API running." });
});

app.listen(PORT, () => console.log(`\n🔫 No Man's Land v2 on port ${PORT}`));
