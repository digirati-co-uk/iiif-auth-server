FROM ubuntu

RUN apt-get update -y && apt-get install -y python-pip python-dev build-essential nginx uwsgi uwsgi-plugin-python
COPY iiifauth.nginx.conf /etc/nginx/sites-available/iiifauth
COPY iiifauth /opt/iiifauth
COPY run_server.sh /opt/iiifauth/
COPY runflask.sh /opt/iiifauth/
COPY requirements.txt /opt/iiifauth/
COPY iiifauth.ini /opt/iiifauth/

RUN ln -s /etc/nginx/sites-available/iiifauth /etc/nginx/sites-enabled/iiifauth && rm -f /etc/nginx/sites-enabled/default
RUN pip install -r /opt/iiifauth/requirements.txt
RUN mkdir /opt/iiifauth/tmp
WORKDIR /opt/iiifauth
EXPOSE 8000

CMD /opt/iiifauth/run_server.sh
