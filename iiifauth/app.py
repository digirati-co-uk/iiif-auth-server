"""
    Handles IIIF info.json and image requests, using iiif2
    Enforces auth as per http://iiif.io/api/auth/1.0/
"""

import os
import re
import json
import uuid
import iiifauth.terms
import sqlite3
from datetime import timedelta

from flask import (
    Flask, make_response, request, session, g, url_for,
    render_template, redirect, send_file, jsonify
)
from iiif2 import iiif, web



app = Flask(__name__)
app.permanent_session_lifetime = timedelta(minutes=10)
app.secret_key = 'Set a sensible secret key here'
app.database = os.path.join(app.root_path, 'iiifauth.db')

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

    return make_acao_response(jsonify(new_manifest), 200)


def make_acao_response(response_object, status=None):
    """We're handling CORS directly for clarity"""
    resp = make_response(response_object, status)
    resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp


def preflight():
    """Handle a CORS preflight request"""
    resp = make_acao_response('', 200)
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

    cookiekey = None
    match = re.search('Bearer (.*)', request.headers.get('Authorization', ''))
    if match:
        token = match.group(1)
        print('token %s found' % token)
        db_token = query_db('select * from tokens where token=?',
                            [token], one=True)
        if db_token:
            cookiekey = db_token['cookiekey']
            print('cookiekey %s found' % cookiekey)
    else:
        print('no Authorization header found')

    if not cookiekey:
        print('requires access control and no cookiekey found')
        return False

    # Now make sure the token is for one of this image's services
    services = policy.get('auth_services', [])
    identifier_slug = 'shared' if policy.get('shared', False) else identifier
    for service in services:
        pattern = get_pattern_name(service)
        test_key = get_key('cookie', pattern, identifier_slug)
        if cookiekey == test_key:
            print('User has cookie key', cookiekey, 'request authorized')
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
    resp = redirect(url_for('image_info', identifier=identifier), code=303)
    return make_acao_response(resp)


@app.route('/img/<identifier>/info.json', methods=['GET', 'OPTIONS'])
def image_info(identifier):
    """
        Return the info.json, with the correct HTTP status code,
        and decorated with the right auth services

        Handle CORS explicitly for clarity
    """
    print("METHOD:", request.method)
    if request.method == 'OPTIONS':
        print('CORS preflight request for', identifier)
        return preflight()

    print('info.json request for', identifier)
    policy = AUTH_POLICY[identifier]
    uri = "%simg/%s" % (request.url_root, identifier)
    info = web.info(uri, resolve(identifier))
    decorate_info(info, policy, identifier)

    if authorise_info_request(identifier):
        resp = make_acao_response(jsonify(info), 200)
        if not policy.get('open'):
            resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        return resp

    print('The user is not authed for this resource')
    degraded_version = policy.get('degraded', None)
    if degraded_version:
        redirect_to = "%s%s/info.json" % (request.url_root, degraded_version)
        print('a degraded version is available at', redirect_to)
        return make_acao_response(redirect(redirect_to, code=302))

    return make_acao_response(jsonify(info), 401)




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
    cookiekey = get_key('cookie', pattern, identifier)
    print('Making a session for ', cookiekey)
    print('origin is ', origin)
    # The token can be anything, but you shouldn't be able to
    # deduce the cookie value from the token value.
    # In this demo the client cookie is a Flask session cookie,
    # we're not setting an explicit IIIF auth cookie.
    token = uuid.uuid4().hex
    print('minted token:', token)
    session[cookiekey] = token

    database = get_db()
    database.execute('insert into tokens (cookiekey, token, origin) '
                     'values (?, ?, ?)',  [cookiekey, token, origin])
    database.commit()


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
    cookiekey = get_key('cookie', pattern, identifier)
    token = session.get(cookiekey, None)
    token_object = None
    db_token = None
    if token:
        db_token = query_db('select * from tokens where token=?',
                            [token], one=True)
    if db_token:
        session_origin = db_token['origin']
        if origin == session_origin or pattern == 'external':
            # don't enforce origin on external auth
            token_object = {
                "accessToken": token,
                "expiresIn": 600
            }
        else:
            print("session origin was %s" % session_origin)
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
    cookiekey = get_key('cookie', pattern, identifier)
    token = session.get(cookiekey)
    session.pop(cookiekey, None)
    database = get_db()
    database.execute('delete from tokens where token=?', token)
    database.commit()
    return "You are now logged out"

# Database to hold map of sessions to tokens issued
# you can't access the session object in an info.json request, because no credentials supplied

def connect_db():
    """Connects to the specific database."""
    rv = sqlite3.connect(app.database)
    rv.row_factory = sqlite3.Row
    return rv

def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = connect_db()
    return g.sqlite_db


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()

def init_db():
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()

@app.cli.command('initdb')
def initdb_command():
    """Initializes the database."""
    init_db()
    print('Initialized the database.')


if __name__ == '__main__':
    app.run()
 