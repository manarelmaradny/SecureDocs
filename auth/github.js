const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;
const { PrismaClient } = require('@prisma/client');


//initialize prisma
const prisma = new PrismaClient();


// configure passport to use the github strategy
passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: '/auth/github/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails?.[0]?.value || `${profile.username}@github.fake`;
    const user = await prisma.user.upsert({
      where: { email },
      update: {},
      create: {
        email,
        name: profile.displayName || profile.username,
        githubId: profile.id,
        role: 'USER'
      }
    });
    return done(null, user);
  } catch (err) {
    return done(err, null);
  }
}));
