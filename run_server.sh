#!/bin/bash

service nginx restart

sleep 1

echo "forcing first log rotation"
logrotate -f /etc/logrotate.conf

uwsgi --ini /opt/iiifauth/iiifauth.ini

