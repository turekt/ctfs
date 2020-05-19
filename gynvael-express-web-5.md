# Gynvael Coldwind ExpressJS challenge 5

Source: https://twitter.com/gynvael/status/1262434816714313729

## Challenge

We are provided with this code on the web page:
```javascript
const http = require('http')
const express = require('express')
const fs = require('fs')
const path = require('path')

const PORT = 5005
const FLAG = process.env.FLAG || "???"
const SOURCE = fs.readFileSync(path.basename(__filename))

const app = express()

app.use(express.urlencoded({extended: false}))

app.post('/flag', (req, res) => {
  res.statusCode = 200
  res.setHeader('Content-Type', 'text/plain;charset=utf-8')

  if (req.body.secret !== 'ShowMeTheFlag') {
    res.end("Say the magic phrase!")
    return
  }

  if (req.youAreBanned) {
    res.end("How about no.")
    return
  }

  res.end(FLAG)
})

app.get('/', (req, res) => {
  res.statusCode = 200
  res.setHeader('Content-Type', 'text/plain;charset=utf-8')
  res.write("Level 5\n\n")
  res.end(SOURCE)
})

const proxy = function(req, res) {
  req.youAreBanned = false
  let body = ''
  req
    .prependListener('data', (data) => { body += data })
    .prependListener('end', () => {
      const o = new URLSearchParams(body)
      req.youAreBanned = o.toString().includes("ShowMeTheFlag")
    })
  return app(req, res)
}

const server = http.createServer(proxy)
server.listen(PORT, () => {
  console.log(`Challenge listening at port ${PORT}`)
})
```

## Analysis

OK, so this is similar to the previous level. We need to get the flag by complying to two constraints:
- `req.body.secret === 'ShowMeTheFlag'`
- `!req.youAreBanned`

We can supply `secret=ShowMeTheFlag` payload easily to `/flag` endpoint, but the `end` listener will set `youAreBanned` to `true`:
```javascript
.prependListener('end', () => {
    const o = new URLSearchParams(body)
    req.youAreBanned = o.toString().includes("ShowMeTheFlag")
})
```

I also noticed this (`extended` param):
```javascript
app.use(express.urlencoded({extended: false}))
```

Looking into [the documentation](https://expressjs.com/en/api.html#express.urlencoded) the `extended` parameter is used to define which URL encoded data parser library to use (querystring vs qs). This made me [search for specific payloads](https://github.com/expressjs/express/blob/master/test/express.urlencoded.js) that could be supplied to querystring.parse, but in the end did not make sense since `ShowMeTheFlag` should be supplied to the HTTP body in full which would make the `youAreBanned` property set to `true`.

Another look into the same documentation showed an additional `inflate` parameter that was not defined inside the code (meaning that it is set to `true`):
> Enables or disables handling deflated (compressed) bodies; when disabled, deflated bodies are rejected.

What if we supply gzip compressed payload?

## Solution

Since `inflate` is set to `true`, Express will decompress gzip payloads to `req.body`, but the end listener will work with raw `body` data which will not contain `ShowMeTheFlag` string. Therefore, we will be able to bypass `youAreBanned` switch, whereas `req.body.secret` will be decompressed and parsed properly.

```sh
$ echo -n 'secret=ShowMeTheFlag' | gzip | curl "http://challenges.gynvael.stream:5005/flag" -H "Content-Encoding: gzip" --data-binary @-
CTF{||SameAsLevel4ButDifferent||}
``` 
