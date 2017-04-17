# iiif-auth-server

A demo server implementation of all apsects of the [IIIF Authentication specification](http://iiif.io/api/auth/1.0/). It shows:

* The Login interaction pattern
* The Clickthrough interaction pattern
* The Kiosk interaction pattern
* The External interaction pattern
* "All or nothing" and degraded image access
* Token and Cookie services

This is a work in progress, please raise issues! It is intended to assist client development by providing a live implementation to test against.

It uses https://github.com/rogerhoward/iiify as base simple server. It's a Flask app that uses Pillow via [iiif2](https://github.com/mekarpeles/iiif2) to generate image tiles. `iiif-auth-server` adds an IIIF auth implementation to demonstrate the different interaction patterns, the cookie services, and the token service.

The latest version of this application should be running at [https://iiifauth.digtest.co.uk/](https://iiifauth.digtest.co.uk/).

There is an accompanying JavaScript client application to run against the server demo at [https://github.com/digirati-co-uk/iiif-auth-client](https://github.com/digirati-co-uk/iiif-auth-client).

This is not a production application! A typical institutional implementation would likely protect many thousands of images with the same cookie and token services, whereas this demo makes you authenticate for most of the sample images separately. It also gives access to everyone's session for diagnostic purposes, has one hardcoded username and password for Login pattern cookie services, and so on. However, it should exercise every part of the specification.


## Usage

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