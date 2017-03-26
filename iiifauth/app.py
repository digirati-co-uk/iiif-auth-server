"""
    Handles IIIF info.json and image requests, using iiif2
    Enforces auth as per http://iiif.io/api/auth/1.0/
"""

import os
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
    if request.method == 'OPTIONS':
        return preflight()

    uri = "%s%s" % (request.url_root, identifier)
    return jsonify(web.info(uri, resolve(identifier)))


@app.route('/<identifier>/<region>/<size>/<rotation>/<quality>.<fmt>')
def image_processor(identifier, **kwargs):
    params = web.Parse.params(identifier, **kwargs)
    tile = iiif.IIIF.render(resolve(identifier), **params)
    return send_file(tile, mimetype=tile.mime)

    
if __name__ == '__main__':
    app.run()