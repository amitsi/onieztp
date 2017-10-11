FROM python:3

ENV NGINX_VERSION 1.13.5-2~jessie

RUN pip install flask uwsgi flask_sqlalchemy

RUN apt-key adv --keyserver hkp://pgp.mit.edu:80 --recv-keys 573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62 \
        && echo "deb http://nginx.org/packages/mainline/debian/ jessie nginx" >> /etc/apt/sources.list \
	&& apt-get update \
	&& apt-get install -y \
		nginx=${NGINX_VERSION} \
		supervisor \
	&& rm -rf /var/lib/apt/lists/*

# nginx
RUN ln -sf /dev/stdout /var/log/nginx/access.log \
	&& ln -sf /dev/stderr /var/log/nginx/error.log
EXPOSE 80

RUN echo "daemon off;" >> /etc/nginx/nginx.conf
RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/

COPY uwsgi.ini /etc/uwsgi/

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

ENV UWSGI_INI /app/uwsgi.ini

# Add demo app
COPY ./app /app
WORKDIR /app
RUN pip install --editable .

ENV FLASK_APP onie
ENV FLASK_DEBUG true

RUN flask initdb

CMD ["/usr/bin/supervisord"]
