"""
    Handles IIIF info.json and image requests, using iiif2
    Enforces auth as per http://iiif.io/api/auth/1.0/
"""

import os
import re
import json
import uuid
import iiifauth.terms
from datetime import timedelta

from flask import (
    Flask, make_response, request, session, url_for,
    render_template, redirect, send_file, jsonify
)
from iiif2 import iiif, web



app = Flask(__name__)
app.permanent_session_lifetime = timedelta(minutes=10)
app.secret_key = 'Set a sensible secret key here'

# some globals
APP_PATH = os.path.dirname(os.path.abspath(__file__))
MEDIA_ROOT = os.path.join(APP_PATH, 'media')
AUTH_POLICY = None
with open(os.path.join(MEDIA_ROOT, 'policy.json')) as policy_data:
    AUTH_POLICY = json.load(policy_data)


@app.before_request
def func():
  session.permanent = True
  session.modified = True


def resolve(identifier):
    """Resolves a iiif identifier to the resource's path on disk."""
    return os.path.join(MEDIA_ROOT, identifier)


@app.route('/')
def index():
    """List all the info.jsons we have"""
    files = os.listdir(MEDIA_ROOT)
    images = sorted(f for f in files if not f.endswith('json') and not f.startswith('manifest'))
    manifests = sorted(''.join(f.split('.')[:-2]) for f in files if f.endswith('manifest.json'))
    return render_template('index.html', images=images, manifests=manifests)

@app.route('/manifest/<identifier>')
def manifest(identifier):
    """
        Transform skeleton manifest into one with sensible URLs
    """
    with open(os.path.join(MEDIA_ROOT, '%s.manifest.json' % identifier)) as source_manifest:
        new_manifest = json.load(source_manifest)
        new_manifest['@id'] = "%smanifest/%s" % (request.url_root, identifier)
        new_manifest['sequences'][0]['@id'] = (
            "%smanifest/%s/sequence" % (request.url_root, identifier))
        for canvas in new_manifest['sequences'][0]['canvases']:
            image = canvas['images'][0]['resource']
            image_identifier = image['@id']
            canvas['images'][0]['@id'] = "%simage-annos/%s" % (request.url_root, image_identifier)
            image['service'] = {
                "@context" : iiifauth.terms.CONTEXT_IMAGE,
                "@id" : "%simg/%s" % (request.url_root, image_identifier),
                "profile" : iiifauth.terms.PROFILE_IMAGE
            }
            image['@id'] = "%s/full/full/0/default.jpg" % image['service']['@id']

    return jsonify(new_manifest)



def preflight():
    """Handle a CORS preflight request"""
    resp = make_response(None, 200)
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'Authorization'
    return resp



def get_pattern_name(service):
    """
        Get a friendly pattern name / slug from the auth service profile
    """
    return service['profile'].split('/')[-1]


def decorate_info(info, policy, identifier):
    """
        Augment the info.json with auth service(s) from our
        'database' of auth policy
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
    policy = AUTH_POLICY[identifier]
    if policy.get('open'):
        print('%s is open, no auth required' % identifier)
        return True

    session_key = None
    match = re.search('Bearer (.*)', request.headers.get('Authorization', ''))
    if match:
        token = match.group(1)
        print('token %s found', token)
        session_key = session.get(token, None)
        print('session_key %s found', session_key)
    else:
        print('no Authorization header found')

    if not session_key:
        print('requires access control and no session_key found')
        return False

    # Now make sure the token is for one of this image's services
    services = policy.get('auth_services', [])
    identifier_slug = 'shared' if policy.get('shared', False) else identifier
    for service in services:
        pattern = get_pattern_name(service)
        test_key = get_key('cookie', pattern, identifier_slug)
        if session_key == test_key:
            print('User has session key', session_key, 'request authorized')
            return True

    print('info request is NOT authorized')
    return False


def authorise_image_request(identifier):
    """
        Authorise image API requests based on Cookie (or possibly other mechanisms)
    """
    policy = AUTH_POLICY[identifier]
    if policy.get('open'):
        return True

    services = policy.get('auth_services', [])
    identifier_slug = 'shared' if policy.get('shared', False) else identifier
    # does the request have a cookie acquired from this image's cookie service(s)?
    for service in services:
        pattern = get_pattern_name(service)
        test_key = get_key('cookie', pattern, identifier_slug)
        if session.get(test_key, None):
            return True

    # handle other possible authorisation mechanisms, such as IP
    return False


@app.route('/img/<identifier>')
def image_id(identifier):
    """Redirect a plain image id"""
    return redirect(url_for('image_info', identifier=identifier), code=303)


@app.route('/img/<identifier>/info.json')
def image_info(identifier):
    """
        Return the info.json, with the correct HTTP status code,
        and decorated with the right auth services

        Handle CORS explicitly for clarity
    """
    if request.method == 'OPTIONS':
        print('CORS preflight request for', identifier)
        return preflight()

    print('info.json request for', identifier)
    policy = AUTH_POLICY[identifier]
    uri = "%s%s" % (request.url_root, identifier)
    info = web.info(uri, resolve(identifier))
    decorate_info(info, policy, identifier)


    if authorise_info_request(identifier):
        return jsonify(info)

    print('The user is not authed for this resource')
    degraded_version = policy.get('degraded', None)
    if degraded_version:
        redirect_to = "%s%s/info.json" % (request.url_root, degraded_version)
        print('a degraded version is available at', redirect_to)
        return redirect(redirect_to, code=302)


    return make_response(jsonify(info), 401)




@app.route('/img/<identifier>/<region>/<size>/<rotation>/<quality>.<fmt>')
def image_api_request(identifier, **kwargs):
    """
        A IIIF Image API request; use iiif2 to generate the tile
    """
    if authorise_image_request(identifier):
        params = web.Parse.params(identifier, **kwargs)
        tile = iiif.IIIF.render(resolve(identifier), **params)
        return send_file(tile, mimetype=tile.mime)

    return make_response("Not authorised", 401)


@app.route('/auth/cookie/<pattern>/<identifier>', methods=['GET', 'POST'])
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
        Your own n a production application
    """
    cookie_key = get_key('cookie', pattern, identifier)
    print('Making a session for ', cookie_key)
    # The token can be anything, but you shouldn't be able to
    # deduce the cookie value from the token value.
    # In this demo the client cookie is a Flask session cookie,
    # we're not setting an explicit IIIF auth cookie.
    token = uuid.uuid4().hex
    print('minted token:', token)
    session[cookie_key] = token
    session[token] = cookie_key
    # store the origin associated with this token
    session[token + '-origin'] = origin


def get_key(key_type, pattern, identifier):
    """
        Simple format for session keys used to maintain session
    """
    return "%s/%s/%s" % (key_type, pattern, identifier)


def split_key(key):
    """Get the pattern and the identifier out of the key"""
    parts = key.split('/')
    return {
        "pattern" : parts[1],
        "identifier": parts[2]
    }


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
    token = session.get(cookie_key, None)
    token_object = None
    if token:
        session_origin = session.get(token + '-origin', None)   
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
        return render_template('token.html', token_object=token_object, origin=origin)

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
 