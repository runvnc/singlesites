express = require 'express'

fs = require 'fs'
path = require 'path'
passport = require 'passport'
LocalStrategy = require('passport-local').Strategy
util = require 'util'

domain = 'oic.io'

S4 = ->  (((1+Math.random())*0x10000)|0).toString(16).substring(1)
process.guid = -> S4()+S4()+"-"+S4()+"-"+S4()+"-"+S4()+"-"+S4()+S4()+S4()

users = [
  { id: 1, username: 'bob', password: 'secret', email: 'bob@example.com' }
  { id: 2, username: 'joe', password: 'birthday', email: 'joe@example.com' }
]


findById = (id, fn) ->
  console.log 'find by id'
  idx = id - 1
  if users[idx]?
    fn null, users[idx]
  else
    fn new Error('User ' + id + ' does not exist')
  

findByUsername = (username, fn) ->
  console.log  'inside of findbyusername'
  for user in users
    if user.username is username
      return fn(null, user)
  return fn(null, null)


passport.serializeUser = (user, done) ->
  console.log 'serializeuser'
  done null, user.id


passport.deserializeUser = (id, done) ->
  console.log 'deserializeuser'
  findById id, (err, user) ->
    done err, user
  

passportfunc = (username, password, done) ->
  console.log 'inside of passportfunc'
  return
  process.nextTick ->
    console.log 'nexttick'
    findByUsername username, (err, user) ->
      console.log 'findbyusername returned'
      if err? then return done(err)
      if not user? then return done(null, false, {message: 'Unknown user ' + username})
      if user.password isnt password then return done(null, false, {message: 'Invalid password'})
      return done(null, user)

passport.use(new LocalStrategy(passportfunc))
 

#httpsopts =
#  key: fs.readFileSync('/etc/selfcert/server.key')
#  cert: fs.readFileSync('/etc/selfcert/server.crt')

#apps = express.createServer httpsopts

app = express.createServer()

app.configure ->
  app.use express.cookieParser()
  app.use express.bodyParser()
  app.use express.session({ secret: 'choc rain' })
  app.use passport.initialize()
  app.use passport.session()
  app.use app.router


checkbasic = (site, req, res, callback) ->
  header = req.headers['authorization'] || ''
  token = header.split(/\s+/).pop() || ''
  auth = new Buffer(token, 'base64').toString()
  parts = auth.split(/:/)
  username = parts[0]
  password = parts[1]
  if not username? or username.length is 0
    sendbad site, res
    return

  fs.readFile 'secrets/'+site+username, 'utf8', (err, data) ->
    if err?
      console.log 'Error reading file ' + 'secrets/'+site+username + ':'
      console.log err
      callback 'none'
    else
      header = req.headers['authorization'] || ''
      token = header.split(/\s+/).pop() || ''
      auth = new Buffer(token, 'base64').toString()
      parts = auth.split(/:/)
      username = parts[0]
      password = parts[1]
      if not username? or username.length is 0
        sendbad site, res
        return
      bcrypt.compare password, data, (err, ret) ->
        console.log 'bcrypt ran compare and ret is ' + ret
        callback ret

sendbad = (site, res) ->
  res.header 'WWW-Authenticate', 'Basic realm="Secure Area"'
  res.send 'Bad password', 401


sendsite = (site, res) ->
  fs.readFile 'public/' + site + '.html', 'utf8', (err, data) ->
    res.send data

makepass = (site, req, res) ->
  fs.readFile 'makepass.html', 'utf8', (err, data) ->
    res.send data

ensureAuthenticated = (req, res, next) ->
  if req.isAuthenticated()
    return next()
  else
    res.redirect '/login'


which = (req, res) ->
  tokens = req.headers.host.split('.')
  if tokens.length is 2
    site = 'www'
    console.log 'trying to call guid'
    code = process.guid()
    launchcodes[code] = true
    res.cookie 'referred', code
  else
    site = tokens[0]
  return site

savecode = (site, req, res) ->
  code = '<!DOCTYPE html><html>' + req.param('html') + '</html>'
  fs.writeFile 'public/' + site + '.html', code, 'utf8', (err) ->
    res.send 'Saved page.'

launch = (template, sitename, req, res) ->
  if req.cookies? and req.cookies.referred? and launchcodes[req.cookies.referred]?
    path.exists 'templates/'+template+'.html', (exists) ->
      if exists
        fs.readFile 'templates/'+template+'.html', 'utf8', (err, data) ->
          if not err?
            fs.writeFile 'public/'+sitename+'.html', data, 'utf8', (err) ->
              if not err?
                res.redirect 'http://'+sitename + '.' + domain
          else
            console.log 'Error reading template file'
            console.log err
      else
        res.send 'Could not find template file: ' + template + '.html'
  else
    res.send 'Invalid'
    console.log 'cookies is '
    console.log req.cookies
    console.log 'launchcodes:'
    console.log launchcodes

launchcodes = {}

app.post '/launch', (req, res) ->
  launch req.body.template, req.body.site, req, res

app.get '/', (req, res) ->
  site = which req, res
  sendsite site, res

app.get '/editok', (req, res) ->
  res.send 'editok'

app.get '/account', ensureAuthenticated, (req, res) ->
  res.send 'User data: ' + util.inspect req.user
  #res.render 'account', { user: req.user }

app.get '/login', (req, res) ->
  console.log 'getting login'
  fs.readFile 'login.html', 'utf8', (err, data) ->
    res.send data

app.post '/login', ->
  console.log 'post to login'
  ret = (req, res) ->
    console.log 'authenticated ok'
    res.redirect '/editok'

  passport.authenticate('local', {failureRedirect:'/loginNO', failureFlash: false}, ret)

app.get '/logout',(req, res) ->
  req.logout()
  res.redirect '/'

app.get '/edit', (req, res, next) ->
  site = which req
  if req.isAuthenticated()
    console.log 'isauthenticated is true'
    sendsite site, res
  else
    console.log 'isauthenticated is false'
    res.redirect '/login'
  #  #if ret is 'none'
  #  #  makepass site, req, res
  #  else if ret is true
  #    sendsite site, res
  #  else
  #    sendbad site, res

app.post '/savepass', (req, res) ->
  site = which req
  path.exists 'secrets/' + site + req.body.username, (exists) ->
    if not exists
      bcrypt.genSalt 10, (err, salt) ->
        bcrypt.hash req.body.password, salt, (err, hash) ->
          fs.writeFile 'secrets/'+site+req.body.username, hash, 'utf8', (err) ->
            res.send 'OK'

app.post '/savecode', (req, res) ->
  site = which req
  if site isnt 'www'
    checkbasic site, req, res, (ret) ->
      if ret is 'none'
        makepass site, req, res
      else if ret is true
        savecode site, req, res
      else
        sendbad site, res
   

#app.use express.static(__dirname + '/public')


app.listen 8080
#apps.listen 3000

