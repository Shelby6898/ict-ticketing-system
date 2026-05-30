require('dotenv').config();

const express     = require('express');
const cors        = require('cors');
const fs          = require('fs');
const path        = require('path');
const helmet      = require('helmet');
const morgan      = require('morgan');
const compression = require('compression');
const rateLimit   = require('express-rate-limit');

const REQUIRED_ENV = ['JWT_SECRET', 'BASE_URL'];
REQUIRED_ENV.forEach(key => {
  if (!process.env[key]) {
    console.error(`Missing required env var: ${key}`);
    process.exit(1);
  }
});

const app  = express();
const PORT = process.env.PORT || 5000;

app.set('trust proxy', 1);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(cors({ origin: process.env.CORS_ORIGIN?.split(',') || '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200, message: { error: 'Too many requests.' } }));

const BOT_PATHS = ['/wp-admin', '/.env', '/phpmyadmin', '/.git', '/xmlrpc'];
app.use((req, res, next) => {
  if (BOT_PATHS.some(p => req.path.startsWith(p))) {
    console.warn(`Blocked bot: ${req.ip} -> ${req.path}`);
    return res.status(403).end();
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  let html = fs.readFileSync(path.join(__dirname, 'public/index.html'), 'utf8');
  html = html.replace(
    /const API = ['"].*?['"]/g,
    `const API = '${process.env.BASE_URL}/api'`
  );
  res.send(html);
});

app.use('/api/auth',    require('./routes/auth'));
app.use('/api/tickets', require('./routes/tickets'));
app.use('/api',         require('./routes/admin'));
app.use('/api/export',  require('./routes/export'));
app.use('/api/tickets/:id/comments', require('./routes/comments'));

app.use((err, req, res, _next) => {
  console.error('[ERROR]', err.message || err);
  res.status(500).json({ error: 'Internal server error.' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
