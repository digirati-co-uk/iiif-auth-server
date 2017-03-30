"""
    Handles IIIF info.json and image requests, using iiif2
    Enforces auth as per http://iiif.io/api/auth/1.0/
"""

import os
import re
import json
import uuid
import iiifauth.terms

from flask import (
    Flask, make_response, request, session, url_for,
    render_template, redirect, send_file, jsonify
)
from iiif2 import iiif, web



app = Flask(__name__)
app.permanent_session_lifetime = timedelta(minutes=10)
path = os.path.dirname(os.path.abspath(__file__))
media_root = os.path.join(path, 'media')


@app.before_request
def func():
  session.permanent = True
  session.modified = True


def resolve(identifier):
    """Resolves a iiif identifier to the resource's path on disk."""
    return os.path.join(media_root, identifier)


@app.route('/')
def index():
    """List all the info.jsons we have"""
    images = sorted(f for f in os.listdir(media_root) if not f.endswith('json'))
    return render_template('index.html', images=images)
    # return jsonify({'identifiers': [f for f in os.listdir(media_root)]})


def preflight():
    """Handle a CORS preflight request"""
    resp = make_response(None, 200)
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'Authorization'
    return resp

def get_policy(identifier):
    with open(os.path.join(media_root, 'policy.json')) as policy_data:
        policy = json.load(policy_data)
        return policy[identifier]

def get_pattern_name(service):
    """
        Use the profile to differentiate pattern names 
    """
    return service['profile'].split('/')[-1]


def decorate_info(info, policy, identifier):
    """
        Flesh out auth services
    """
    services = policy.get('auth_services', [])

    for service in services:
        service['@context'] = iiifauth.terms.CONTEXT_AUTH
        pattern = get_pattern_name(service)
        identifier_slug = 'shared' if policy.get('shared', False) else identifier
        service['@id'] = "%sauth/cookie/%s/%s" % (request.url_root, pattern, identifier_slug)
        service['service'] = [
            {
                "@id" : "%sauth/token/%s/%s" % (request.url_root, pattern, identifier_slug),
                "profile" : iiifauth.terms.PROFILE_TOKEN
            },
            {
                "@id" : "%sauth/logout/%s/%s" % (request.url_root, pattern, identifier_slug),
                "profile" : iiifauth.terms.PROFILE_LOGOUT,
                "label": "log out"
            }
        ]

    if len(services) == 1:
        info['service'] = services[0]
    else:
        info['service'] = services


def authorise_info_request(identifier):
    """Authorise info.json request based on token"""
    policy = get_policy(identifier)

    token = None
    m = re.search('Bearer (.*)', request.headers.get('Authorization', ''))
    if m:
        token = m.group(1)

    if policy.get('open', False):
        return True

    return True

def authorise_image_request(identifier):
    policy = get_policy(identifier)
    # does the request have a cookie acquired from this image's cookie service(s)?
    return True


@app.route('/<identifier>/info.json')
def image_info(identifier):
    """
        Return the info.json, with the correct HTTP status code,
        and decorated with the right auth services

        Handle CORS explicitly for clarity
    """
    if request.method == 'OPTIONS':
        # CORS preflight request
        return preflight()

    policy = get_policy(identifier)
    uri = "%s%s" % (request.url_root, identifier)
    info = web.info(uri, resolve(identifier))
    decorate_info(info, policy, identifier)


    if authorise_info_request(identifier):
        return jsonify(info)
    
    # not authed!
    if policy.degraded:
        return redirect("%s%s" % (request.url_root, policy.degraded), code=302)


    return make_response(jsonify(info), 401)




@app.route('/<identifier>/<region>/<size>/<rotation>/<quality>.<fmt>')
def image_api_request(identifier, **kwargs):
    """
        A IIIF Image API request; use iiif2 to generate the tile
    """
    if authorise_image_request(identifier):
        params = web.Parse.params(identifier, **kwargs)
        tile = iiif.IIIF.render(resolve(identifier), **params)
        return send_file(tile, mimetype=tile.mime)

    return make_response("Not authorised", 401)


@app.route('/auth/cookie/<pattern>/<identifier>')
def cookie_service(pattern, identifier):
    """Cookie service (might be a login interaction pattern. Doesn't have to be)"""
    origin = request.args.get('origin')

    if pattern == 'login':
        return handle_login(pattern, identifier, origin, 'login.html')

    elif pattern == 'clickthrough':
        return successful_login(pattern, identifier, origin)

    elif pattern == 'kiosk':
        return successful_login(pattern, identifier, origin)

    elif pattern == 'external':
        return make_response("Error - a client should not call an "
                             "external auth cookie service @id", 400)


def handle_login(pattern, identifier, origin, template):
    """
        Handle login GETs and POSTs
    """
    error = None
    if request.method == 'POST':
        if request.form['username'] != 'username':
            error = 'Invalid username'
        elif request.form['password'] != 'password':
            error = 'Invalid password'
        else:
            return successful_login(pattern, identifier, origin)

    return render_template(template, error=error)


def successful_login(pattern, identifier, origin):
    """
        Create a new session and direct the user to a self-closing window
    """
    resp = redirect(url_for('post_login'))
    make_session(pattern, identifier, origin)
    return resp


@app.route('/external-cookie/<identifier>')
def external(identifier):
    """This is a 'secret' login page"""
    return handle_login('external', identifier, None, 'external.html')


def make_session(pattern, identifier, origin):
    """
        Establish a session for this user and this resource.
        Needless to say, do not follow this pattern in a production application
    """
    cookie_key = get_key('cookie', pattern, identifier)
    token = uuid.uuid4().hex
    session[cookie_key] = token
    session[token] = cookie_key
    session[token + '-origin'] = origin


def get_key(key_type, profile, identifier):
    """
        Simple format for session keys used to maintain session
    """
    return "%s/%s/%s" % (key_type, profile, identifier)


@app.route('/auth/post_login')
def post_login():
    """render a window-closing page"""
    return render_template('post_login.html')



@app.route('/auth/token/<pattern>/<identifier>')
def token_service(pattern, identifier):
    """Token service"""
    origin = request.args.get('origin')
    message_id = request.args.get('messageId')
    cookie_key = get_key('cookie', pattern, identifier)
    token = session.get(cookie_key)
    session_origin = session.get(token + '-origin', None)
    token_object = None
    if token:
        if origin == session_origin or pattern == 'external':
            # don't enforce origin on external auth
            token_object = {
                "accessToken": token,
                "expiresIn": 600
            }
        else:
            token_object = {
                "error": "invalidOrigin",
                "description": "Not the origin supplied at login"
            }
    else:
        token_object = {
            "error": "missingCredentials",
            "description": "to be filled out"
        }

    if message_id:
        # client is a browser
        token_object['messageId'] = message_id
        return render_template('token.html', token=token_object, origin=origin)

    # client isn't using postMessage
    return jsonify(token_object)


@app.route('/auth/logout/<pattern>/<identifier>')
def logout_service(pattern, identifier):
    """Log out service"""
    cookie_key = get_key('cookie', pattern, identifier)
    token = session.get(cookie_key)
    session.pop(cookie_key, None)
    session.pop(token, None)
    session.pop(token + '-origin', None)
    return "You are now logged out"


if __name__ == '__main__':
    app.run()
