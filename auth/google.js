const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const user = await prisma.user.upsert({
      where: { email: profile.emails[0].value },
      update: {},
      create: {
        email: profile.emails[0].value,
        name: profile.displayName,
        googleId: profile.id,
        role: 'USER'
      }
    });
    return done(null, user);
  } catch (err) {
    return done(err, null);
  }
}));
