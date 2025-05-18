const express = require('express');
const session = require('express-session');
const passport = require('passport');
const fs = require('fs');
const https = require('https');
const morgan = require('morgan');
const path = require('path');
require('dotenv').config();

// Passport strategies
require('./auth/okta');
require('./auth/google');
require('./auth/github');

const app = express();

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));

app.use(session({
  secret: 'your_super_secret',
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// Set EJS as the templating engine
app.set('view engine', 'ejs');

// Set the views directory (where .ejs files are located)
app.set('views', path.join(__dirname, 'views'));

// Prisma & session handling
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await prisma.user.findUnique({ where: { id } });
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Routes
const authRoutes = require('./routes/auth');
const twofaRoutes = require('./routes/2fa');
const dashboardRoutes = require('./routes/dashboard');
const uploadRoutes = require('./routes/uploads');
const profileRoutes = require('./routes/profile');
const forgotPasswordRoutes = require('./routes/forgotPassword');

app.use('/', profileRoutes)
app.use('/', authRoutes);
app.use('/', twofaRoutes);
app.use('/', dashboardRoutes);
app.use('/', uploadRoutes);
app.use('/', forgotPasswordRoutes);


// HTTPS server
const sslOptions = {
  key: fs.readFileSync('./cert/key.pem'),
  cert: fs.readFileSync('./cert/cert.pem')
};

https.createServer(sslOptions, app).listen(3000, () => {
  console.log('SecureDocs running at https://localhost:3000');
});
