# Gynvael Coldwind ExpressJS challenge 6

Source: https://twitter.com/gynvael/status/1264504663791058945

## Challenge

We are provided with this code on the web page:
```javascript
const http = require('http')
const express = require('express')
const fs = require('fs')
const path = require('path')

const PORT = 5006
const FLAG = process.env.FLAG || "???"
const SOURCE = fs.readFileSync(path.basename(__filename))

const app = express()

const checkSecret = (secret) => {
  return
    [
      secret.split("").reverse().join(""),
      "xor",
      secret.split("").join("-")
    ].join('+')
}

app.get('/flag', (req, res) => {
  res.statusCode = 200
  res.setHeader('Content-Type', 'text/plain;charset=utf-8')

  if (!req.query.secret1 || !req.query.secret2) {
    res.end("You are not even trying.")
    return
  }

  if (`<${checkSecret(req.query.secret1)}>` === req.query.secret2) {
    res.end(FLAG)
    return
  }

  res.end("Lul no.")
})

app.get('/', (req, res) => {
  res.statusCode = 200
  res.setHeader('Content-Type', 'text/plain;charset=utf-8')
  res.write("Level 6\n\n")
  res.end(SOURCE)
})

app.listen(PORT, () => {
  console.log(`Example app listening at port ${PORT}`)
})
```

## Analysis

This one got me there for a few minutes. Let's try to break this down, we need to:
- set both `req.query.secret1` and `req.query.secret2`
- match the return value of `<${checkSecret(secret1)}>` and `secret2`

At first my thought was: "ez, for `secret1=a` we have `<a+xor+a>` as a result of the template string, we just have to watch out because `+` is interpreted as space in expressjs. But that didn't work:
```sh
$ curl "http://challenges.gynvael.stream:5006/flag?secret1=a&secret2=<a%2Bxor%2Ba>"
Lul no.
```

It came to me after running the code in the browser console that the newline between the return and the return value in `checkSecret` will make it return `undefined` (note the warning and the result of the function):
```javascript
> const checkSecret = (secret) => {
.   return
.     [
.       secret.split("").reverse().join(""),
.       "xor",
.       secret.split("").join("-")
.     ].join('+')
. }
.
undefined
! unreachable code after return statement       2 debugger eval code:3:4
> checkSecret(1)
undefined
```

## Solution

Since `checkSecret` will always return `undefined`, `secret1` param is not relevant, it just needs to be set. The `secret2` param should be set to `<undefined>` so we can get the flag:

```sh
$ curl "http://challenges.gynvael.stream:5006/flag?secret1=a&secret2=<undefined>"
CTF{||RevengeOfTheScript||}
```
