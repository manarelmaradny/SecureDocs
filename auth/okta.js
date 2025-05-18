const passport = require('passport');
const OAuth2Strategy = require('passport-oauth2').Strategy;
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

passport.use('okta', new OAuth2Strategy({
  authorizationURL: `${process.env.OKTA_ISSUER}/v1/authorize`,
  tokenURL: `${process.env.OKTA_ISSUER}/v1/token`,
  clientID: process.env.OKTA_CLIENT_ID,
  clientSecret: process.env.OKTA_CLIENT_SECRET,
  callbackURL: 'https://localhost:3000/auth/okta/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    // Okta doesn't provide profile by default, so use the token to fetch user info
    const res = await fetch(`${process.env.OKTA_ISSUER}/v1/userinfo`, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    const userInfo = await res.json();

    // Save or find user in DB
    const user = await prisma.user.upsert({
      where: { email: userInfo.email },
      update: {},
      create: {
        email: userInfo.email,
        name: userInfo.name || 'No Name',
        role: 'USER'
      }
    });

    done(null, user);
  } catch (err) {
    done(err, null);
  }
}));
