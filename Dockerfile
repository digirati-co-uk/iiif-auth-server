FROM ubuntu

RUN apt-get update -y && apt-get install -y python-pip python-dev build-essential nginx uwsgi uwsgi-plugin-python libjpeg-dev
COPY requirements.txt /opt/iiif/requirements.txt
RUN pip install -r /opt/iiif/requirements.txt

COPY etc/iiifauth.nginx.conf /etc/nginx/sites-available/iiifauth
RUN ln -s /etc/nginx/sites-available/iiifauth /etc/nginx/sites-enabled/iiifauth && rm -f /etc/nginx/sites-enabled/default

# write out nginx logs to stdout/stderr
RUN ln -sf /dev/stdout /var/log/nginx/access.log && ln -sf /dev/stdout /var/log/nginx/error.log

WORKDIR /opt/iiif
EXPOSE 443

COPY iiifauth /opt/iiif/iiifauth

COPY run_server.sh /opt/iiif/
COPY iiifauth.ini /opt/iiif/
COPY wsgi.py /opt/iiif/
COPY database.py /opt/iiif/

RUN cd /opt/iiif && export FLASK_APP='iiifauth' && python database.py

CMD /opt/iiif/run_server.sh

