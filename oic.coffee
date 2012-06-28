express = require 'express'
app = express.createServer()
fs = require 'fs'
path = require 'path'

app.use express.bodyParser()


checkbasic = (site, req, res, callback) ->
  header = req.headers['authorization'] || ''
  token = header.split(/\s+/).pop() || ''
  auth = new Buffer(token, 'base64').toString()
  parts = auth.split(/:/)
  username = parts[0]
  password = parts[1]
  fs.readFile 'secrets/'+site, 'utf8', (err, data) ->
    if err?
      callback 'none'
    else
      if data is username + password
        callback true
      else
        callback false

sendbad = (site, res) ->
  res.header 'WWW-Authenticate', 'Basic realm="Secure Area"'
  res.send 'Bad password', 401


sendsite = (site, res) ->
  fs.readFile 'public/' + site + '.html', 'utf8', (err, data) ->
    res.send data

makepass = (site, req, res) ->
  fs.readFile 'makepass.html', 'utf8', (err, data) ->
    res.send data

which = (req) ->
  tokens = req.headers.host.split('.')
  if tokens.length is 2
    site = 'www'
  else
    site = tokens[0]

savecode = (site, req, res) ->
  code = '<!DOCTYPE html><html>' + req.param('html') + '</html>'
  fs.writeFile 'public/' + site + '.html', code, 'utf8', (err) ->
    res.send 'Saved page.'


app.get '/', (req, res) ->
  site = which req
  sendsite site, res


app.get '/edit', (req, res) ->
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
  path.exists 'secrets/' + site, (exists) ->
    if not exists
      dat = req.body.username + req.body.password
      fs.writeFile 'secrets/'+site, dat, 'utf8', (err) ->
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
   

app.use express.static(__dirname + '/public')


app.listen 8080


