FROM ubuntu

RUN apt-get update -y && apt-get install -y python-pip python-dev build-essential nginx uwsgi uwsgi-plugin-python logrotate libjpeg-dev
COPY requirements.txt /opt/iiif/requirements.txt
RUN pip install -r /opt/iiif/requirements.txt

COPY etc/nginx.logrotate /etc/logrotate.d/nginx
COPY etc/logrotate.conf /etc/logrotate.conf
RUN chmod 600 /etc/logrotate.conf && chmod 600 /etc/logrotate.d/nginx

COPY etc/iiifauth.nginx.conf /etc/nginx/sites-available/iiifauth
RUN ln -s /etc/nginx/sites-available/iiifauth /etc/nginx/sites-enabled/iiifauth && rm -f /etc/nginx/sites-enabled/default

WORKDIR /opt/iiif
EXPOSE 443

COPY iiifauth /opt/iiif/iiifauth

COPY run_server.sh /opt/iiif/
COPY iiifauth.ini /opt/iiif/
COPY wsgi.py /opt/iiif/
COPY database.py /opt/iiif/

RUN cd /opt/iiif && python database.py

CMD /opt/iiif/run_server.sh
