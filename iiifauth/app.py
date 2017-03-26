"""
    Handles IIIF info.json and image requests, using iiif2
    Enforces auth as per http://iiif.io/api/auth/1.0/
"""

import os
import re
import json
from flask import Flask, Response, make_response, send_file, jsonify, request, render_template, url_for
from iiif2 import iiif, web


app = Flask(__name__)
path = os.path.dirname(os.path.abspath(__file__))
media_root = os.path.join(path, 'media')


def resolve(identifier):
    """Resolves a iiif identifier to the resource's path on disk."""
    return os.path.join(media_root, identifier)


@app.route('/')
def index():
    """List all the info.jsons we have"""
    images = sorted(f for f in os.listdir(media_root))
    return render_template('index.html', images=images)
    # return jsonify({'identifiers': [f for f in os.listdir(media_root)]})


def preflight():
    """Handle a CORS preflight request"""
    resp = make_response(None, 200)
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'Authorization'
    return resp



@app.route('/<identifier>/info.json')
def image_info(identifier):
    """
        Return the info.json, with the correct HTTP status code,
        and decorated with the right auth services
    """
    if request.method == 'OPTIONS':
        return preflight()

    token = None
    m = re.search('Bearer (.*)', request.headers.get('Authorization', ''))
    if m:
        token = m.group(1)  

    uri = "%s%s" % (request.url_root, identifier)
    info = web.info(uri, resolve(identifier))

    

    # get service info
    # decorate with services
    # determine user's status wrt img
    # token on request?

    return jsonify(info)


@app.route('/<identifier>/<region>/<size>/<rotation>/<quality>.<fmt>')
def image_processor(identifier, **kwargs):
    params = web.Parse.params(identifier, **kwargs)
    tile = iiif.IIIF.render(resolve(identifier), **params)
    return send_file(tile, mimetype=tile.mime)

@app.route('/<identifier>/cookie')
def cookie_service(identifier):
    """Cookie service (might be a login interaction patterm doesn't have to be)"""
    origin = request.args.get('origin')
    # look up identifier in list
    # might be a special shared identifier or prefix that applies to more than one image
    # /iiif/login



@app.route('/<identifier>/token')
def token_service(identifier):
    """Token service"""
    origin = request.args.get('origin')
    messageId = request.args.get('messageId')


@app.route('/<identifier>/logout')
def logout_service(identifier):
    """Log out service"""
    # identifier might be 'all'


    
if __name__ == '__main__':
    app.run()