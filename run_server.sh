#!/bin/bash

service nginx restart
uwsgi --ini /opt/iiifauth/iiifauth.ini

