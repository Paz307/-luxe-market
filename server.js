const express = require('express');
const session = require('express-session');
const flash = require('connect-flash');
const path = require('path');

const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Serve HTML files as EJS
app.engine('html', require('ejs').renderFile);
app.set('view engine', 'html');

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: 'luxemarket_secret_2024',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 }
}));

app.use(flash());

const routes = require('./routes/auth');
app.use('/', routes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n✦ Luxe Market running at http://localhost:${PORT}\n`);
});
