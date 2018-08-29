#!/bin/bash

service nginx restart

sleep 1

cd /opt/iiif && uwsgi --ini /opt/iiif/iiifauth.ini

