FROM python:3

ENV NGINX_VERSION 1.13.5-2~jessie

RUN pip install \
	cryptography \
	flask \
	flask_sqlalchemy \
	netaddr \
	requests \
	uwsgi

RUN apt-key adv --keyserver hkp://pgp.mit.edu:80 --recv-keys 573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62 \
        && echo "deb http://nginx.org/packages/mainline/debian/ jessie nginx" >> /etc/apt/sources.list \
	&& apt-get update \
	&& apt-get install -y \
		isc-dhcp-server \
		nginx=${NGINX_VERSION} \
		supervisor \
	&& rm -rf /var/lib/apt/lists/*

# nginx
RUN ln -sf /dev/stdout /var/log/nginx/access.log \
	&& ln -sf /dev/stderr /var/log/nginx/error.log

RUN echo "daemon off;" >> /etc/nginx/nginx.conf
RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/

COPY uwsgi.ini /etc/uwsgi/

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

RUN mkdir -p /var/www/html/images/license_10g \
	/var/www/html/images/license_40g \
	/var/www/html/images/ansible_hosts

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

# XXX: TEST CODE BEGIN
COPY dhcpd.conf.sample /etc/dhcp/dhcpd.conf
# XXX: TEST CODE END

COPY ./run.sh /
CMD ["/run.sh"]
