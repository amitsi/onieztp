# onieztp

Create a DJANGO based tool to do ONIE, Software Upgrade and Make it available for pncheck troubleshooting


docker build 'https://github.com/amitsi/onieztp.git#:onie/docker'

amitsi-5:~ amitsingh$ docker image ls
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
<none>              <none>              cc24247b3d7f        2 minutes ago       726MB
python              3                   01fd71a97c19        26 hours ago        690MB


amitsi-5:~ amitsingh$ docker run cc24247b3d7f
/usr/lib/python2.7/dist-packages/supervisor/options.py:296: UserWarning: Supervisord is running as root and it is searching for its configuration file in default locations (including its current working directory); you probably want to specify a "-c" argument specifying an absolute path to a configuration file for improved security.
  'Supervisord is running as root and it is searching '
2017-10-11 04:45:24,783 CRIT Supervisor running as root (no user in config file)
2017-10-11 04:45:24,783 WARN Included extra file "/etc/supervisor/conf.d/supervisord.conf" during parsing
2017-10-11 04:45:24,790 INFO RPC interface 'supervisor' initialized
2017-10-11 04:45:24,790 CRIT Server 'unix_http_server' running without any HTTP authentication checking
2017-10-11 04:45:24,790 INFO supervisord started with pid 1
2017-10-11 04:45:25,793 INFO spawned: 'nginx' with pid 9
2017-10-11 04:45:25,795 INFO spawned: 'uwsgi' with pid 10
[uWSGI] getting INI configuration from /app/uwsgi.ini
[uWSGI] getting INI configuration from /etc/uwsgi/uwsgi.ini
*** Starting uWSGI 2.0.15 (64bit) on [Wed Oct 11 04:45:25 2017] ***
compiled with version: 4.9.2 on 11 October 2017 04:35:19
os: Linux-4.9.49-moby #1 SMP Wed Sep 27 23:17:17 UTC 2017
nodename: fb2a1e7ebe4a
machine: x86_64
clock source: unix
pcre jit disabled
detected number of CPU cores: 4
current working directory: /app
detected binary path: /usr/local/bin/uwsgi
your memory page size is 4096 bytes
detected max file descriptor number: 1048576
lock engine: pthread robust mutexes
thunder lock: disabled (you can enable it with --thunder-lock)
uwsgi socket 0 bound to UNIX address /tmp/uwsgi.sock fd 3
uWSGI running as root, you can use --uid/--gid/--chroot options
*** WARNING: you are running uWSGI as root !!! (use the --uid flag) ***
Python version: 3.6.3 (default, Oct 10 2017, 02:29:16)  [GCC 4.9.2]
*** Python threads support is disabled. You can enable it with --enable-threads ***
Python main interpreter initialized at 0xcf6e50
your server socket listen backlog is limited to 100 connections
your mercy for graceful operations on workers is 60 seconds
mapped 1237056 bytes (1208 KB) for 16 cores
*** Operational MODE: preforking ***
WSGI app 0 (mountpoint='') ready in 1 seconds on interpreter 0xcf6e50 pid: 10 (default app)
*** uWSGI is running in multiple interpreter mode ***
spawned uWSGI master process (pid: 10)
spawned uWSGI worker 1 (pid: 13, cores: 1)
spawned uWSGI worker 2 (pid: 14, cores: 1)
2017-10-11 04:45:27,245 INFO success: nginx entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
2017-10-11 04:45:27,246 INFO success: uwsgi entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)

amitsi-5:~ amitsingh$ docker exec -it fb2a1e7ebe4a bash
root@fb2a1e7ebe4a:/app# ifconfig
bash: ifconfig: command not found
root@fb2a1e7ebe4a:/app# ifconfig -a
bash: ifconfig: command not found
root@fb2a1e7ebe4a:/app# apt-get install nettools
Reading package lists... Done
Building dependency tree
Reading state information... Done
E: Unable to locate package nettools
root@fb2a1e7ebe4a:/app# apt-get update
Get:1 http://security.debian.org jessie/updates InRelease [63.1 kB]
Get:2 http://nginx.org jessie InRelease [2865 B]
Ign http://deb.debian.org jessie InRelease
Get:3 http://deb.debian.org jessie-updates InRelease [145 kB]
Get:4 http://deb.debian.org jessie Release.gpg [2373 B]
Get:5 http://deb.debian.org jessie Release [148 kB]
Get:6 http://security.debian.org jessie/updates/main amd64 Packages [547 kB]
Get:7 http://nginx.org jessie/nginx amd64 Packages [36.0 kB]
Get:8 http://deb.debian.org jessie-updates/main amd64 Packages [23.1 kB]
Get:9 http://deb.debian.org jessie/main amd64 Packages [9063 kB]
Fetched 10.0 MB in 5s (1938 kB/s)
Reading package lists... Done
root@fb2a1e7ebe4a:/app# ip link
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: tunl0@NONE: <NOARP> mtu 1480 qdisc noop state DOWN mode DEFAULT group default qlen 1
    link/ipip 0.0.0.0 brd 0.0.0.0
3: gre0@NONE: <NOARP> mtu 1476 qdisc noop state DOWN mode DEFAULT group default qlen 1
    link/gre 0.0.0.0 brd 0.0.0.0
4: gretap0@NONE: <BROADCAST,MULTICAST> mtu 1462 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
5: ip_vti0@NONE: <NOARP> mtu 1332 qdisc noop state DOWN mode DEFAULT group default qlen 1
    link/ipip 0.0.0.0 brd 0.0.0.0
6: ip6_vti0@NONE: <NOARP> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1
    link/tunnel6 :: brd ::
7: sit0@NONE: <NOARP> mtu 1480 qdisc noop state DOWN mode DEFAULT group default qlen 1
    link/sit 0.0.0.0 brd 0.0.0.0
8: ip6tnl0@NONE: <NOARP> mtu 1452 qdisc noop state DOWN mode DEFAULT group default qlen 1
    link/tunnel6 :: brd ::
9: ip6gre0@NONE: <NOARP> mtu 1448 qdisc noop state DOWN mode DEFAULT group default qlen 1
    link/gre6 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00 brd 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
33: eth0@if34: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
root@fb2a1e7ebe4a:/app#

Sample first Run on a MAC (will update later)

amitsi-5:~ amitsingh$ docker build 'https://github.com/amitsi/onieztp.git#:onie/docker'
Sending build context to Docker daemon  18.94kB
Step 1/20 : FROM python:3
3: Pulling from library/python
85b1f47fba49: Pull complete
5409e9a7fa9e: Pull complete
661393707836: Pull complete
1bb98c08d57e: Pull complete
c842a08369e2: Pull complete
85dae9ff820c: Pull complete
86149ff515a2: Pull complete
4aaec9c0a093: Pull complete
Digest: sha256:f90ee14d0fa02bfe8e27517a906c9ed54552ff0939c3713a3d2aeeb68444e7d1
Status: Downloaded newer image for python:3
 ---> 01fd71a97c19
Step 2/20 : ENV NGINX_VERSION 1.13.5-2~jessie
 ---> Running in 15eea72dbf24
 ---> 3675300ae3cc
Removing intermediate container 15eea72dbf24
Step 3/20 : RUN pip install flask uwsgi flask_sqlalchemy
 ---> Running in 12b505d7eecd
Collecting flask
  Downloading Flask-0.12.2-py2.py3-none-any.whl (83kB)
Collecting uwsgi
  Downloading uwsgi-2.0.15.tar.gz (795kB)
Collecting flask_sqlalchemy
  Downloading Flask_SQLAlchemy-2.3.1-py2.py3-none-any.whl
Collecting Werkzeug>=0.7 (from flask)
  Downloading Werkzeug-0.12.2-py2.py3-none-any.whl (312kB)
Collecting itsdangerous>=0.21 (from flask)
  Downloading itsdangerous-0.24.tar.gz (46kB)
Collecting Jinja2>=2.4 (from flask)
  Downloading Jinja2-2.9.6-py2.py3-none-any.whl (340kB)
Collecting click>=2.0 (from flask)
  Downloading click-6.7-py2.py3-none-any.whl (71kB)
Collecting SQLAlchemy>=0.8.0 (from flask_sqlalchemy)
  Downloading SQLAlchemy-1.1.14.tar.gz (5.2MB)
Collecting MarkupSafe>=0.23 (from Jinja2>=2.4->flask)
  Downloading MarkupSafe-1.0.tar.gz
Building wheels for collected packages: uwsgi, itsdangerous, SQLAlchemy, MarkupSafe
  Running setup.py bdist_wheel for uwsgi: started
  Running setup.py bdist_wheel for uwsgi: finished with status 'done'
  Stored in directory: /root/.cache/pip/wheels/26/d0/48/e7b0eed63b5d191e89d94e72196aafae93b2b6505a9feafdd9
  Running setup.py bdist_wheel for itsdangerous: started
  Running setup.py bdist_wheel for itsdangerous: finished with status 'done'
  Stored in directory: /root/.cache/pip/wheels/fc/a8/66/24d655233c757e178d45dea2de22a04c6d92766abfb741129a
  Running setup.py bdist_wheel for SQLAlchemy: started
  Running setup.py bdist_wheel for SQLAlchemy: finished with status 'done'
  Stored in directory: /root/.cache/pip/wheels/9f/cc/4b/d2645b72ec1ba3dd72d7ae384c431cf56bae03918f38c4e5e5
  Running setup.py bdist_wheel for MarkupSafe: started
  Running setup.py bdist_wheel for MarkupSafe: finished with status 'done'
  Stored in directory: /root/.cache/pip/wheels/88/a7/30/e39a54a87bcbe25308fa3ca64e8ddc75d9b3e5afa21ee32d57
Successfully built uwsgi itsdangerous SQLAlchemy MarkupSafe
Installing collected packages: Werkzeug, itsdangerous, MarkupSafe, Jinja2, click, flask, uwsgi, SQLAlchemy, flask-sqlalchemy
Successfully installed Jinja2-2.9.6 MarkupSafe-1.0 SQLAlchemy-1.1.14 Werkzeug-0.12.2 click-6.7 flask-0.12.2 flask-sqlalchemy-2.3.1 itsdangerous-0.24 uwsgi-2.0.15
 ---> 0a532cac2e88
Removing intermediate container 12b505d7eecd
Step 4/20 : RUN apt-key adv --keyserver hkp://pgp.mit.edu:80 --recv-keys 573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62         && echo "deb http://nginx.org/packages/mainline/debian/ jessie nginx" >> /etc/apt/sources.list 	&& apt-get update 	&& apt-get install -y 		nginx=${NGINX_VERSION} 		supervisor 	&& rm -rf /var/lib/apt/lists/*
 ---> Running in 23ecc8b2a8f5
Executing: gpg --ignore-time-conflict --no-options --no-default-keyring --homedir /tmp/tmp.3YliqSBHlN --no-auto-check-trustdb --trust-model always --primary-keyring /etc/apt/trusted.gpg --keyring /etc/apt/trusted.gpg.d/debian-archive-jessie-automatic.gpg --keyring /etc/apt/trusted.gpg.d/debian-archive-jessie-security-automatic.gpg --keyring /etc/apt/trusted.gpg.d/debian-archive-jessie-stable.gpg --keyring /etc/apt/trusted.gpg.d/debian-archive-stretch-automatic.gpg --keyring /etc/apt/trusted.gpg.d/debian-archive-stretch-security-automatic.gpg --keyring /etc/apt/trusted.gpg.d/debian-archive-stretch-stable.gpg --keyring /etc/apt/trusted.gpg.d/debian-archive-wheezy-automatic.gpg --keyring /etc/apt/trusted.gpg.d/debian-archive-wheezy-stable.gpg --keyserver hkp://pgp.mit.edu:80 --recv-keys 573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62
gpg: requesting key 7BD9BF62 from hkp server pgp.mit.edu
gpgkeys: key 573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62 can't be retrieved
gpg: no valid OpenPGP data found.
gpg: Total number processed: 0
The command '/bin/sh -c apt-key adv --keyserver hkp://pgp.mit.edu:80 --recv-keys 573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62         && echo "deb http://nginx.org/packages/mainline/debian/ jessie nginx" >> /etc/apt/sources.list 	&& apt-get update 	&& apt-get install -y 		nginx=${NGINX_VERSION} 		supervisor 	&& rm -rf /var/lib/apt/lists/*' returned a non-zero code: 2
amitsi-5:~ amitsingh$
