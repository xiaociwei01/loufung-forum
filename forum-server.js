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
    const mPostDel = p.match(/^\/api\/posts\/(\d+)$/);
    if (mPostDel && req.method === 'DELETE') return handleDeletePost(req, res, Number(mPostDel[1]));
    const mCmtDel = p.match(/^\/api\/comments\/(\d+)$/);
    if (mCmtDel && req.method === 'DELETE') return handleDeleteComment(req, res, Number(mCmtDel[1]));
    const mPostLike = p.match(/^\/api\/posts\/(\d+)\/like$/);
    if (mPostLike && req.method === 'POST') return handleLikePost(req, res, Number(mPostLike[1]));
    const mPostShare = p.match(/^\/api\/posts\/(\d+)\/share$/);
    if (mPostShare && req.method === 'POST') return handleSharePost(req, res, Number(mPostShare[1]));
    const mPostFav = p.match(/^\/api\/posts\/(\d+)\/fav$/);
    if (mPostFav && req.method === 'POST') return handleFavPost(req, res, Number(mPostFav[1]));
    const mLike = p.match(/^\/api\/comments\/(\d+)\/like$/);
    if (mLike && req.method === 'POST') return handleLikeComment(req, res, Number(mLike[1]));
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
    "SELECT p.id, p.title, p.content, strftime('%Y-%m-%d %H:%M', p.created_at, '+8 hours') as created_at, u.username, (SELECT COUNT(*) FROM post_likes pl WHERE pl.post_id = p.id) as like_count, (SELECT COUNT(*) FROM post_shares ps WHERE ps.post_id = p.id) as share_count, (SELECT COUNT(*) FROM post_favorites pf WHERE pf.post_id = p.id) as fav_count, (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id AND c.status = 'approved') as comment_count FROM posts p JOIN users u ON u.id = p.user_id WHERE p.status = ? ORDER BY p.id DESC LIMIT 100"
  ).all('approved');
  sendJSON(res, 200, { posts: rows });
}

function handleGetPost(req, res, id) {
  const me = getSession(req);
  const meId = me ? me.id : -1;

  const post = db.prepare(
    "SELECT p.id, p.title, p.content, strftime('%Y-%m-%d %H:%M', p.created_at, '+8 hours') as created_at, u.username, (SELECT COUNT(*) FROM post_likes pl WHERE pl.post_id = p.id) as like_count, (SELECT COUNT(*) FROM post_likes pl WHERE pl.post_id = p.id AND pl.user_id = ?) as liked_by_me, (SELECT COUNT(*) FROM post_shares ps WHERE ps.post_id = p.id) as share_count, (SELECT COUNT(*) FROM post_favorites pf WHERE pf.post_id = p.id) as fav_count, (SELECT COUNT(*) FROM post_favorites pf WHERE pf.post_id = p.id AND pf.user_id = ?) as faved_by_me, (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id AND c.status = 'approved') as comment_count FROM posts p JOIN users u ON u.id = p.user_id WHERE p.id = ? AND p.status = ?"
  ).get(meId, meId, id, 'approved');
  if (!post) return sendJSON(res, 404, { error: '帖子不存在' });

  const rows = db.prepare(
    "SELECT c.id, c.content, c.parent_id, strftime('%Y-%m-%d %H:%M', c.created_at, '+8 hours') as created_at, u.username, (SELECT COUNT(*) FROM comment_likes cl WHERE cl.comment_id = c.id) as like_count, (SELECT COUNT(*) FROM comment_likes cl WHERE cl.comment_id = c.id AND cl.user_id = ?) as liked_by_me FROM comments c JOIN users u ON u.id = c.user_id WHERE c.post_id = ? AND c.status = ? ORDER BY c.id ASC"
  ).all(meId, id, 'approved');

  // 组装树形
  const map = {};
  rows.forEach(r => { r.replies = []; map[r.id] = r; });
  const top = [];
  rows.forEach(r => {
    if (r.parent_id && map[r.parent_id]) {
      map[r.parent_id].replies.push(r);
    } else {
      top.push(r);
    }
  });
  sendJSON(res, 200, { post, comments: top });
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
  const parentId = data.parent_id ? Number(data.parent_id) : null;
  if (!postId) return sendJSON(res, 400, { error: '缺少帖子 ID' });
  if (content.length < 1 || content.length > 2000) return sendJSON(res, 400, { error: '评论 1-2000 字' });
  const post = db.prepare('SELECT id FROM posts WHERE id = ? AND status = ?').get(postId, 'approved');
  if (!post) return sendJSON(res, 404, { error: '帖子不存在' });
  if (parentId) {
    const parent = db.prepare('SELECT id FROM comments WHERE id = ? AND post_id = ?').get(parentId, postId);
    if (!parent) return sendJSON(res, 400, { error: '被回复的评论不存在' });
  }
  const info = db.prepare(
    'INSERT INTO comments (post_id, user_id, content, status, parent_id) VALUES (?, ?, ?, ?, ?)'
  ).run(postId, user.id, content, 'approved', parentId);
  sendJSON(res, 200, { ok: true, id: info.lastInsertRowid });
}


function handleLikeComment(req, res, id) {
  const user = getSession(req);
  if (!user) return sendJSON(res, 401, { error: '请先登录' });
  const comment = db.prepare('SELECT id FROM comments WHERE id = ?').get(id);
  if (!comment) return sendJSON(res, 404, { error: '评论不存在' });
  const liked = db.prepare('SELECT 1 FROM comment_likes WHERE user_id = ? AND comment_id = ?').get(user.id, id);
  if (liked) {
    db.prepare('DELETE FROM comment_likes WHERE user_id = ? AND comment_id = ?').run(user.id, id);
    sendJSON(res, 200, { ok: true, liked: false });
  } else {
    db.prepare('INSERT INTO comment_likes (user_id, comment_id) VALUES (?, ?)').run(user.id, id);
    sendJSON(res, 200, { ok: true, liked: true });
  }
}


function handleLikePost(req, res, id) {
  const user = getSession(req);
  if (!user) return sendJSON(res, 401, { error: '请先登录' });
  const post = db.prepare('SELECT id FROM posts WHERE id = ? AND status = ?').get(id, 'approved');
  if (!post) return sendJSON(res, 404, { error: '帖子不存在' });
  const liked = db.prepare('SELECT 1 FROM post_likes WHERE user_id = ? AND post_id = ?').get(user.id, id);
  if (liked) {
    db.prepare('DELETE FROM post_likes WHERE user_id = ? AND post_id = ?').run(user.id, id);
    sendJSON(res, 200, { ok: true, liked: false });
  } else {
    db.prepare('INSERT INTO post_likes (user_id, post_id) VALUES (?, ?)').run(user.id, id);
    sendJSON(res, 200, { ok: true, liked: true });
  }
}

function handleFavPost(req, res, id) {
  const user = getSession(req);
  if (!user) return sendJSON(res, 401, { error: '请先登录' });
  const post = db.prepare('SELECT id FROM posts WHERE id = ? AND status = ?').get(id, 'approved');
  if (!post) return sendJSON(res, 404, { error: '帖子不存在' });
  const fav = db.prepare('SELECT 1 FROM post_favorites WHERE user_id = ? AND post_id = ?').get(user.id, id);
  if (fav) {
    db.prepare('DELETE FROM post_favorites WHERE user_id = ? AND post_id = ?').run(user.id, id);
    sendJSON(res, 200, { ok: true, fav: false });
  } else {
    db.prepare('INSERT INTO post_favorites (user_id, post_id) VALUES (?, ?)').run(user.id, id);
    sendJSON(res, 200, { ok: true, fav: true });
  }
}


function handleSharePost(req, res, id) {
  const user = getSession(req);
  if (!user) return sendJSON(res, 401, { error: '请先登录' });
  const post = db.prepare('SELECT id FROM posts WHERE id = ? AND status = ?').get(id, 'approved');
  if (!post) return sendJSON(res, 404, { error: '帖子不存在' });
  const existing = db.prepare('SELECT 1 FROM post_shares WHERE user_id = ? AND post_id = ?').get(user.id, id);
  if (!existing) {
    db.prepare('INSERT INTO post_shares (user_id, post_id) VALUES (?, ?)').run(user.id, id);
  }
  const count = db.prepare('SELECT COUNT(*) as c FROM post_shares WHERE post_id = ?').get(id).c;
  sendJSON(res, 200, { ok: true, share_count: count, already: !!existing });
}


function handleDeletePost(req, res, id) {
  const user = getSession(req);
  if (!user) return sendJSON(res, 401, { error: '请先登录' });
  const post = db.prepare('SELECT user_id FROM posts WHERE id = ?').get(id);
  if (!post) return sendJSON(res, 404, { error: '帖子不存在' });
  if (post.user_id !== user.id) return sendJSON(res, 403, { error: '只能删自己的帖子' });
  db.prepare('DELETE FROM posts WHERE id = ?').run(id);
  sendJSON(res, 200, { ok: true });
}

function handleDeleteComment(req, res, id) {
  const user = getSession(req);
  if (!user) return sendJSON(res, 401, { error: '请先登录' });
  const cmt = db.prepare('SELECT user_id FROM comments WHERE id = ?').get(id);
  if (!cmt) return sendJSON(res, 404, { error: '评论不存在' });
  if (cmt.user_id !== user.id) return sendJSON(res, 403, { error: '只能删自己的评论' });
  // 级联：把所有直接/间接子回复也删了
  const ids = [id];
  let queue = [id];
  while (queue.length) {
    const cur = queue.shift();
    const children = db.prepare('SELECT id FROM comments WHERE parent_id = ?').all(cur);
    children.forEach(c => { ids.push(c.id); queue.push(c.id); });
  }
  const placeholders = ids.map(() => '?').join(',');
  db.prepare('DELETE FROM comments WHERE id IN (' + placeholders + ')').run(...ids);
  sendJSON(res, 200, { ok: true, deleted: ids.length });
}

server.listen(PORT, () => {
  console.log('✅ forum-server 运行在 http://localhost:' + PORT);
});
