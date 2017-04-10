#!/bin/bash

service nginx restart

sleep 1

echo "forcing first log rotation"
logrotate -f /etc/logrotate.conf

cd /opt/iiif && uwsgi --ini /opt/iiif/iiifauth.ini

