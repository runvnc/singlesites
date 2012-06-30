express = require 'express'

fs = require 'fs'
path = require 'path'
util = require 'util'
bcrypt = require 'bcrypt'
child_proc = require 'child_process'
connect = require 'connect'

domain = 'oic.io'

S4 = ->  (((1+Math.random())*0x10000)|0).toString(16).substring(1)
process.guid = -> S4()+S4()+"-"+S4()+"-"+S4()+"-"+S4()+"-"+S4()+S4()+S4()


launchcodes = {}


#httpsopts =
#  key: fs.readFileSync('/etc/selfcert/server.key')
#  cert: fs.readFileSync('/etc/selfcert/server.crt')

#apps = express.createServer httpsopts

app = express.createServer()

app.configure ->
  app.use express.cookieParser()
  app.use express.bodyParser()
  app.use connect.compress()
#  app.use express.session({ secret: 'choc rain' })
#  app.use passport.initialize()
#  app.use passport.session()
#  app.use app.router


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

  fs.readFile 'secrets/'+site+'_'+username, 'utf8', (err, data) ->
    if err?
      console.log 'Error reading file ' + 'secrets/'+site+'_'+ username + ':'
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
  console.log 'handling site sendsite ' + site
  fs.readFile 'public/' + site + '.html', 'utf8', (err, data) ->
    if err?
      console.log 'error in sendsite ' + err
    else
      console.log 'sending data'
      res.send data



templates = []

resetwww = ->
  fs.readdir 'public/templates', (err, files) ->
    console.log 'templates files is'
    console.log files
    templates = []
    s = ''
    for f in files
      item = f.replace('.html','')
      templates.push item
      s+= '<img class="item" src="thumbs/'+item+'.png" title="'+item+'"/>'
    fs.readFile 'www.html', 'utf8', (err, data) ->
      data = data.replace('{{templates}}', s)
      fs.readdir 'public', (err, files) ->
         sites = []
         for f in files
           if f.indexOf('.html')>0
             sites.push f
         sitelist = ''
         for s in sites
           x = s.replace('.html','')
           sitelist += '<li><a href="http://'+x+'.'+domain+'/">'+x+'</a></li>'
         data = data.replace('{{sites}}', sitelist)
         fs.writeFile 'public/www.html', data, 'utf8', (err) ->

resetwww()

makepass = (site, req, res) ->
  path.exists 'secrets/'+site + '_configured', (exists) ->
    if exists
      sendbad site, res
      #res.send 'User already configured'
      
    else
      fs.readFile 'makepass.html', 'utf8', (err, data) ->
        res.send data

maketemplate = (site, req, res) ->
  fs.readFile "public/#{site}.html", 'utf8', (err, data) ->
    if not err?
      console.log 'trying to make template thumbnail'
      child_proc.exec "./thumbsite http://#{site}.#{domain}:8080/ public/thumbs/#{site}.png", (err, so, serr) ->
        console.log err
        console.log so
        console.log serr
      fs.writeFile "public/templates/#{site}.html", data, 'utf8', (err) ->
        if not err?
          if not site in templates
            templates.push site
          resetwww()
          fs.readFile 'templatesaved.html', 'utf8', (err, dat) ->
            res.send dat
    else
      console.log 'Error reading site file in maketemplate'
      console.log err


ensureAuthenticated = (req, res, next) ->
  if req.isAuthenticated()
    return next()
  else
    res.redirect '/login'


which = (req, res) ->
  tokens = req.headers.host.split('.')
  if tokens.length is 2 or tokens.length is 1
    site = 'www'
    console.log 'trying to call guid'
    code = process.guid()
    console.log 'assigned launchedcode'
    launchcodes[code] = true
    res.cookie 'referred', code
  else
    console.log 'did not assign launch code this time'
    site = tokens[0]
  return site

savecode = (site, req, res) ->
  code = '<!DOCTYPE html><html>' + req.param('html') + '</html>'
  fs.writeFile 'public/' + site + '.html', code, 'utf8', (err) ->
    res.send 'Saved page.'

launch = (template, sitename, req, res) ->
  if true || req.cookies? and req.cookies.referred? and launchcodes[req.cookies.referred]?
    path.exists 'public/templates/'+template+'.html', (exists) ->
      if exists
        fs.readFile 'public/templates/'+template+'.html', 'utf8', (err, data) ->
          if not err?
            fs.writeFile 'public/'+sitename+'.html', data, 'utf8', (err) ->
              if not err?
                req.theredir = 'http://'+sitename+'.'+domain
                savepass sitename, req, res
                resetwww()
                #res.redirect 'http://'+sitename + '.' + domain
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

app.post '/launch', (req, res) ->
  launch req.body.template, req.body.site, req, res

app.get '/templatelist', (req, res) ->
  res.send JSON.stringify(templates)

app.get '/', (req, res) ->
  console.log 'get ok'
  site = which req, res
  console.log 'site is ' + site
  sendsite site, res

app.post '/maketemplate', (req, res) ->
  site = which req, res
  checkbasic site, req, res, (ret) ->
    if ret
      maketemplate site, req, res

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
  checkbasic site, req, res, (ret) ->
    if ret is 'none'
      makepass site, req, res
    else if ret is true
      sendsite site, res
    else
      sendbad site, res

app.post '/savepass', (req, res) ->
  site = which req
  savepass site, req, res

savepass = (site, req, res) ->
  path.exists 'secrets/' + site + req.body.username, (exists) ->
    if not exists
      bcrypt.genSalt 10, (err, salt) ->
        bcrypt.hash req.body.password, salt, (err, hash) ->
          fs.writeFile 'secrets/'+site+'_'+req.body.username, hash, 'utf8', (err) ->
            fs.writeFile 'secrets/'+site+'_configured', 'ok', 'utf8', ->
            res.redirect 'http://' + site + '.' + domain + '/'

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
   

app.use express.static(__dirname + '/public')

process.on 'uncaughtException', (err) ->
  console.log err

app.listen 8080
#apps.listen 3000

