const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: 'https://localhost:3000/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails[0].value;
    const googleId = profile.id;

    // Check if user exists by googleId
    let user = await prisma.user.findUnique({
      where: { googleId }
    });

    // If not found, fallback to email
    if (!user) {
      user = await prisma.user.findUnique({ where: { email } });

      if (user) {
        // Update existing user with googleId
        user = await prisma.user.update({
          where: { email },
          data: { googleId }
        });
      } else {
        // Create new user
        user = await prisma.user.create({
          data: {
            email,
            name: profile.displayName,
            googleId,
            role: 'USER'
          }
        });
      }
    }

    return done(null, user);
  } catch (err) {
    console.error('Google auth error:', err);
    return done(err, null);
  }
}));
