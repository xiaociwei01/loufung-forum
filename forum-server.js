const http = require('http');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { DatabaseSync } = require('node:sqlite');

const PORT = 3002;
const DB_PATH = path.join(__dirname, 'db', 'forum.db');
const TURNSTILE_SECRET = fs.readFileSync(path.join(__dirname, '.turnstile-secret'), 'utf8').trim();

const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA foreign_keys = ON');

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
function genSalt() {
  return crypto.randomBytes(16).toString('hex');
}
function genToken() {
  return crypto.randomBytes(32).toString('hex');
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > 1e6) req.destroy(); });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

function sendJSON(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body)
  });
  res.end(body);
}

function parseCookies(req) {
  const raw = req.headers.cookie || '';
  const out = {};
  raw.split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}

function verifyTurnstile(token, ip) {
  return new Promise((resolve) => {
    const https = require('https');
    const post = 'secret=' + TURNSTILE_SECRET + '&response=' + token + '&remoteip=' + ip;
    const req = https.request({
      hostname: 'challenges.cloudflare.com',
      path: '/turnstile/v0/siteverify',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(post)
      }
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data).success === true); }
        catch { resolve(false); }
      });
    });
    req.on('error', () => resolve(false));
    req.write(post);
    req.end();
  });
}

function getSession(req) {
  const cookies = parseCookies(req);
  const token = cookies.forum_token;
  if (!token) return null;
  const row = db.prepare(
    'SELECT user_id, expires_at FROM sessions WHERE token = ?'
  ).get(token);
  if (!row) return null;
  if (new Date(row.expires_at) < new Date()) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    return null;
  }
  const user = db.prepare(
    'SELECT id, username FROM users WHERE id = ?'
  ).get(row.user_id);
  return user || null;
}

async function handleRegister(req, res) {
  const body = await readBody(req);
  let data;
  try { data = JSON.parse(body); } catch { return sendJSON(res, 400, { error: '格式错误' }); }

  const username = (data.username || '').trim();
  const password = data.password || '';
  const tsToken = data.turnstile || '';

  if (username.length < 2 || username.length > 20) return sendJSON(res, 400, { error: '用户名 2-20 字' });
  if (!/^[\w\u4e00-\u9fa5]+$/.test(username)) return sendJSON(res, 400, { error: '用户名只能字母数字下划线或中文' });
  if (password.length < 6) return sendJSON(res, 400, { error: '密码至少 6 位' });

  const ip = req.headers['cf-connecting-ip'] || req.socket.remoteAddress || '';
  const ok = await verifyTurnstile(tsToken, ip);
  if (!ok) return sendJSON(res, 400, { error: '人机验证失败' });

  const exist = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (exist) return sendJSON(res, 400, { error: '用户名已存在' });

  const salt = genSalt();
  const hash = hashPassword(password, salt);
  const info = db.prepare(
    'INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)'
  ).run(username, hash, salt);

  sendJSON(res, 200, { ok: true, userId: info.lastInsertRowid });
}

async function handleLogin(req, res) {
  const body = await readBody(req);
  let data;
  try { data = JSON.parse(body); } catch { return sendJSON(res, 400, { error: '格式错误' }); }

  const username = (data.username || '').trim();
  const password = data.password || '';
  if (!username || !password) return sendJSON(res, 400, { error: '用户名密码不能为空' });

  const user = db.prepare(
    'SELECT id, username, password_hash, salt FROM users WHERE username = ?'
  ).get(username);
  if (!user) return sendJSON(res, 400, { error: '用户名或密码错误' });

  const hash = hashPassword(password, user.salt);
  if (hash !== user.password_hash) return sendJSON(res, 400, { error: '用户名或密码错误' });

  const token = genToken();
  const expires = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
  db.prepare(
    'INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)'
  ).run(token, user.id, expires);

  res.setHeader('Set-Cookie',
    'forum_token=' + token + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + (7 * 24 * 3600));
  sendJSON(res, 200, { ok: true, user: { id: user.id, username: user.username } });
}

function handleLogout(req, res) {
  const cookies = parseCookies(req);
  if (cookies.forum_token) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(cookies.forum_token);
  }
  res.setHeader('Set-Cookie', 'forum_token=; Path=/; Max-Age=0');
  sendJSON(res, 200, { ok: true });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;

  try {
    if (!p.startsWith('/api/')) {
      return serveStatic(req, res, p);
    }
    const mPost = p.match(/^\/api\/posts\/(\d+)$/);
    if (p === '/api/posts' && req.method === 'GET') return handleListPosts(req, res);
    if (p === '/api/comments' && req.method === 'POST') return handleCreateComment(req, res);
    if (p === '/api/posts' && req.method === 'POST') return handleCreatePost(req, res);
    if (mPost && req.method === 'GET') return handleGetPost(req, res, Number(mPost[1]));
    if (p === '/api/register' && req.method === 'POST') return handleRegister(req, res);
    if (p === '/api/login' && req.method === 'POST') return handleLogin(req, res);
    if (p === '/api/logout' && req.method === 'POST') return handleLogout(req, res);
    if (p === '/api/me') {
      const user = getSession(req);
      return sendJSON(res, 200, { user });
    }
    sendJSON(res, 404, { error: 'not found' });
  } catch (e) {
    console.error(e);
    sendJSON(res, 500, { error: 'server error' });
  }
});


function serveStatic(req, res, p) {
  if (p === '/') p = '/index.html';
  const safe = p.replace(/\.\./g, '');
  const file = path.join(__dirname, 'public', safe);
  if (!fs.existsSync(file)) return sendJSON(res, 404, { error: 'not found' });
  const ext = path.extname(file);
  const mime = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.png': 'image/png',
    '.svg': 'image/svg+xml'
  }[ext] || 'application/octet-stream';
  res.writeHead(200, { 'Content-Type': mime });
  fs.createReadStream(file).pipe(res);
}


function handleListPosts(req, res) {
  const rows = db.prepare(
    "SELECT p.id, p.title, datetime(p.created_at, '+8 hours') as created_at, u.username FROM posts p JOIN users u ON u.id = p.user_id WHERE p.status = ? ORDER BY p.id DESC LIMIT 100"
  ).all('approved');
  sendJSON(res, 200, { posts: rows });
}

function handleGetPost(req, res, id) {
  const post = db.prepare(
    "SELECT p.id, p.title, p.content, datetime(p.created_at, '+8 hours') as created_at, u.username FROM posts p JOIN users u ON u.id = p.user_id WHERE p.id = ? AND p.status = ?"
  ).get(id, 'approved');
  if (!post) return sendJSON(res, 404, { error: '帖子不存在' });
  const comments = db.prepare(
    "SELECT c.id, c.content, datetime(c.created_at, '+8 hours') as created_at, u.username FROM comments c JOIN users u ON u.id = c.user_id WHERE c.post_id = ? AND c.status = ? ORDER BY c.id ASC"
  ).all(id, 'approved');
  sendJSON(res, 200, { post, comments });
}

async function handleCreatePost(req, res) {
  const user = getSession(req);
  if (!user) return sendJSON(res, 401, { error: '请先登录' });
  const body = await readBody(req);
  let data;
  try { data = JSON.parse(body); } catch { return sendJSON(res, 400, { error: '格式错误' }); }
  const title = (data.title || '').trim();
  const content = (data.content || '').trim();
  if (title.length < 1 || title.length > 100) return sendJSON(res, 400, { error: '标题 1-100 字' });
  if (content.length < 1 || content.length > 10000) return sendJSON(res, 400, { error: '内容 1-10000 字' });
  const info = db.prepare(
    'INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)'
  ).run(user.id, title, content);
  sendJSON(res, 200, { ok: true, id: info.lastInsertRowid });
}


async function handleCreateComment(req, res) {
  const user = getSession(req);
  if (!user) return sendJSON(res, 401, { error: '请先登录' });
  const body = await readBody(req);
  let data;
  try { data = JSON.parse(body); } catch { return sendJSON(res, 400, { error: '格式错误' }); }
  const postId = Number(data.post_id);
  const content = (data.content || '').trim();
  if (!postId) return sendJSON(res, 400, { error: '缺少帖子 ID' });
  if (content.length < 1 || content.length > 2000) return sendJSON(res, 400, { error: '评论 1-2000 字' });
  const post = db.prepare('SELECT id FROM posts WHERE id = ? AND status = ?').get(postId, 'approved');
  if (!post) return sendJSON(res, 404, { error: '帖子不存在' });
  db.prepare(
    'INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)'
  ).run(postId, user.id, content);
  sendJSON(res, 200, { ok: true });
}

server.listen(PORT, () => {
  console.log('✅ forum-server 运行在 http://localhost:' + PORT);
});
