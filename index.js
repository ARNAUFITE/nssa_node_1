const express = require('express')
const logger = require('morgan')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const jwt = require('jsonwebtoken')
const jwtSecret = require('crypto').randomBytes(16) // 16*8=256 random bits 
const cookieParser = require('cookie-parser')
const JwtStrategy = require('passport-jwt').Strategy
const fs = require('fs')
const https = require('https')
const sqlite3 = require('sqlite3').verbose()
const scryptMcf = require('scrypt-mcf')
const { log } = require('console')


const privateKey = fs.readFileSync('server.key', 'utf8')
const certificate = fs.readFileSync('server.cert', 'utf8')
const credentials = { key: privateKey, cert: certificate }

const app = express()
const port = 3000

const db = new sqlite3.Database('./mydb.db', sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
  if (err) {
    console.error(err.message);
  } else {
    console.log('Connected to the mydb.db SQLite database.');
    initializeDatabase();
    registerUser('walrusfast','walrus', 8);
    registerUser('walrusslow','walrus', 20);
  }
});

function initializeDatabase() {
  db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, hash TEXT, salt TEXT)", (err) => {
      if (err) {
        console.error('Error creating table:', err.message);
      } else {
        console.log('Table users is ready.');
      }
    });    
  });
}

async function registerUser(username, password, N) {
  const derivedKeyLength = 64;
  const scryptParams = {
    logN: N,
    r: 8,
    p: 2
  }
  const key = await scryptMcf.hash(password, { derivedKeyLength : derivedKeyLength, scryptParams: scryptParams})
  db.run("INSERT OR REPLACE INTO users (username, hash) VALUES (?,?)", [username, key]);
}

app.use(logger('dev'))
app.use(cookieParser())

passport.use('jwtCookie', new JwtStrategy(
  {
    jwtFromRequest: (req) => {
      if (req && req.cookies) { return req.cookies.jwt }
      return null
    },
    secretOrKey: jwtSecret
  },
  function (jwtPayload, done) {
    if (jwtPayload.sub) {
      const user = { 
        username: jwtPayload.sub,
        description: 'one of the users that deserve to get to this server',
        role: jwtPayload.role ?? 'user'
      }
      return done(null, user)
    }
    return done(null, false)
  }
))

passport.use('username-password', new LocalStrategy(
  {
    usernameField: 'username',
    passwordField: 'password',
    session: false
  },
  function(username, password, done) {
    db.get("SELECT hash FROM users WHERE username = ?", [username], (err, row) => {
      if (err) return done(err);
      if (!row) return done(null, false);

      scryptMcf.verify(password, row.hash).then(result=> {
        if(result){
          return done(null, { username: username });
        }
        else{
          return done(null, false);
        }
      })
    });
  }
));

app.use(express.urlencoded({ extended: true })) 
app.use(passport.initialize()) 

app.get('/',
  passport.authenticate(
    'jwtCookie',
    { session: false, failureRedirect: '/login' }
  ),
  (req, res) => {
    res.send(`Welcome to your private page, ${req.user.username}!`) // we can get the username from the req.user object provided by the jwtCookie strategy
  }
)

app.get('/logout', (req, res) => {
  res.cookie('jwt', '', { expires: new Date(0) });
  res.redirect('/login')
});

app.get('/login',
  (req, res) => {
    res.sendFile('login.html', { root: __dirname })
  }
)

app.post('/login', 
  passport.authenticate('username-password', { failureRedirect: '/login', session: false }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
  (req, res) => {
    // This is what ends up in our JWT
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
      role: 'user' // just to show a private JWT field
    }

    // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
    const token = jwt.sign(jwtClaims, jwtSecret)
    res.username = req.user.username
    res.cookie('jwt', token, { httpOnly: true, secure: true }) // Write the token to a cookie with name 'jwt' and enable the flags httpOnly and secure.
    res.redirect('/')

    // And let us log a link to the jwt.io debugger for easy checking/verifying:
    //console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    //console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
  }
)

app.use(function (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

const httpsServer = https.createServer(credentials, app);

httpsServer.listen(port, () => {
  console.log(`Example app listening at https://localhost:${port}`);
});