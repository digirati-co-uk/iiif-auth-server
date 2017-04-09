# iiif-auth-server
Demo server implementation of IIIF Auth

(in progress)

Uses https://github.com/rogerhoward/iiify as base simple server

It's a Flask app that uses Pillow via iiif2 for images. 

Usage

1. Clone this repo
2. (optional) In the iiif-auth-server directory, set up a virtualenv:
```
python3 -m venv venv
```
3. To install for development:
```
pip install --editable .
```
4. to run for development:
```
export FLASK_APP=iiifauth
export FLASK_DEBUG=true
flask run
```
or
```
. runflask.sh
```

5. Token information is stored in a sqllite3 db, which needs to be initialised:
```
flask initdb
```

Problems - you will need to install jpeg support for pillow if you don't already have it, e.g., on Ubuntu

```
# install libjpeg-dev with apt
sudo apt-get install libjpeg-dev
# if you're on Ubuntu 14.04, also install this
sudo apt-get install libjpeg8-dev

# reinstall pillow
pip install --no-cache-dir -I pillow
```
(from http://stackoverflow.com/questions/8915296)