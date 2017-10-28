FROM python:3

ENV NGINX_VERSION 1.13.5-2~jessie

COPY requirements.txt /tmp/
RUN pip install --requirement /tmp/requirements.txt

RUN apt-key adv --keyserver hkp://pgp.mit.edu:80 --recv-keys 573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62 \
        && echo "deb http://nginx.org/packages/mainline/debian/ jessie nginx" >> /etc/apt/sources.list \
	&& apt-get update \
	&& DEBIAN_FRONTEND=noninteractive apt-get --assume-yes install -yq \
		isc-dhcp-server \
		nginx=${NGINX_VERSION} \
		supervisor \
		tshark \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /ztpvol
RUN mkdir -p html/images nginx \
	&& mkdir -p html/images/license_10g html/images/license_40g html/images/ansible_hosts \
	&& mkdir -p /var/www/html \
	&& ln -sf /ztpvol/html/images /var/www/html/images \
	&& touch nginx/access.log nginx/error.log \
	&& ln -sf /ztpvol/nginx/access.log /var/log/nginx/access.log \
	&& ln -sf /ztpvol/nginx/error.log /var/log/nginx/error.log

RUN touch /var/log/dhcpd.log /var/log/dhcpd.err

RUN echo "daemon off;" >> /etc/nginx/nginx.conf
RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/

COPY uwsgi.ini /etc/uwsgi/

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

ENV UWSGI_INI /app/uwsgi.ini
ENV HTTP_PORT 4000
ENV HTTPS_PORT 4443
ENV DHCP_INTERFACE eth0

WORKDIR /root/certs
RUN openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
	-subj "/C=US/ST=CA/L=Palo Alto/O=Pluribus Networks/OU=Eng/CN=onie.pluribusnetworks.com" \
	-days 3650 -nodes

# Add demo app
COPY ./app /app
WORKDIR /app
RUN pip install --editable .

ENV FLASK_APP onie
ENV FLASK_DEBUG true

RUN flask initdb
RUN flask db init && flask db migrate && flask db upgrade && touch /ztpvol/initdb

COPY ./logcat.sh /
COPY ./tech-support-archive.sh /
COPY ./tshark.sh /

COPY ./run.sh /
CMD ["/run.sh"]
