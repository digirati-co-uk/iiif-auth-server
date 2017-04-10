FROM ubuntu

RUN apt-get update -y && apt-get install -y python-pip python-dev build-essential nginx uwsgi uwsgi-plugin-python logrotate
COPY requirements.txt /opt/iiifauth/requirements.txt
RUN pip install -r /opt/iiifauth/requirements.txt

WORKDIR /opt/iiifauth
EXPOSE 8000

COPY iiifauth /opt/iiifauth
COPY run_server.sh /opt/iiifauth/
COPY iiifauth.ini /opt/iiifauth/

COPY etc/iiifauth.nginx.conf /etc/nginx/sites-available/iiifauth
RUN ln -s /etc/nginx/sites-available/iiifauth /etc/nginx/sites-enabled/iiifauth && rm -f /etc/nginx/sites-enabled/default

COPY etc/nginx.logrotate /etc/logrotate.d/nginx
COPY etc/logrotate.conf /etc/logrotate.conf
RUN chmod 600 /etc/logrotate.conf && chmod 600 /etc/logrotate.d/nginx

CMD /opt/iiifauth/run_server.sh
