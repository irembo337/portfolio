const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

function ensureStorage() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, '[]', 'utf8');
  }
}

function readUsers() {
  ensureStorage();
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch (error) {
    return [];
  }
}

function writeUsers(users) {
  ensureStorage();
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return { salt, hash };
}

function verifyPassword(password, user) {
  const { hash } = hashPassword(password, user.salt);
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(user.passwordHash, 'hex'));
}

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });
  res.end(JSON.stringify(payload));
}

function sendFile(res, filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const contentTypes = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8'
  };

  fs.readFile(filePath, (error, content) => {
    if (error) {
      sendJson(res, 404, { error: 'Файл не найден' });
      return;
    }
    res.writeHead(200, { 'Content-Type': contentTypes[ext] || 'text/plain; charset=utf-8' });
    res.end(content);
  });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 1_000_000) {
        reject(new Error('Слишком большой запрос'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (error) {
        reject(new Error('Некорректный JSON'));
      }
    });
  });
}

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    createdAt: user.createdAt
  };
}

async function handleRegister(req, res) {
  try {
    const { name, email, password } = await readBody(req);
    const cleanName = String(name || '').trim();
    const cleanEmail = String(email || '').trim().toLowerCase();
    const cleanPassword = String(password || '');

    if (!cleanName || !cleanEmail || !cleanPassword) {
      sendJson(res, 400, { error: 'Заполните все поля' });
      return;
    }
    if (!cleanEmail.includes('@')) {
      sendJson(res, 400, { error: 'Введите корректный email' });
      return;
    }
    if (cleanPassword.length < 6) {
      sendJson(res, 400, { error: 'Пароль должен быть минимум 6 символов' });
      return;
    }

    const users = readUsers();
    if (users.some((user) => user.email === cleanEmail)) {
      sendJson(res, 409, { error: 'Пользователь с таким email уже есть' });
      return;
    }

    const passwordData = hashPassword(cleanPassword);
    const user = {
      id: crypto.randomUUID(),
      name: cleanName,
      email: cleanEmail,
      salt: passwordData.salt,
      passwordHash: passwordData.hash,
      createdAt: new Date().toISOString()
    };
    users.push(user);
    writeUsers(users);

    sendJson(res, 201, { message: 'Заявка/регистрация принята сервером', user: publicUser(user) });
  } catch (error) {
    sendJson(res, 400, { error: error.message });
  }
}

async function handleLogin(req, res) {
  try {
    const { email, password } = await readBody(req);
    const cleanEmail = String(email || '').trim().toLowerCase();
    const cleanPassword = String(password || '');
    const users = readUsers();
    const user = users.find((item) => item.email === cleanEmail);

    if (!user || !verifyPassword(cleanPassword, user)) {
      sendJson(res, 401, { error: 'Неверный email или пароль' });
      return;
    }

    sendJson(res, 200, { message: 'Вход выполнен', user: publicUser(user) });
  } catch (error) {
    sendJson(res, 400, { error: error.message });
  }
}

const server = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/api/register') {
    handleRegister(req, res);
    return;
  }
  if (req.method === 'POST' && req.url === '/api/login') {
    handleLogin(req, res);
    return;
  }
  if (req.method === 'GET' && req.url === '/api/health') {
    sendJson(res, 200, { ok: true });
    return;
  }

  const requestedPath = req.url === '/' ? '/index.html' : req.url.split('?')[0];
  const safePath = path.normalize(requestedPath).replace(/^([/\\])+/, '');
  const filePath = path.join(ROOT, safePath);

  if (!filePath.startsWith(ROOT)) {
    sendJson(res, 403, { error: 'Доступ запрещён' });
    return;
  }
  sendFile(res, filePath);
});

ensureStorage();
server.listen(PORT, () => {
  console.log(`Server started: http://localhost:${PORT}`);
});
