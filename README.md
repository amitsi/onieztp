# onieztp

Create a DJANGO based tool to do ONIE, Software Upgrade and Make it available for pncheck troubleshooting






Sample Run on a MAC (will update later)

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
