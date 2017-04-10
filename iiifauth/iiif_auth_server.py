"""
    Handles IIIF info.json and image requests, using iiif2
    Enforces auth as per http://iiif.io/api/auth/1.0/
"""

import os
import re
import json
import uuid
import sqlite3
from datetime import timedelta
from collections import namedtuple

import iiifauth.terms
from flask import (
    Flask, make_response, request, session, g, url_for,
    render_template, redirect, send_file, jsonify
)
from iiif2 import iiif, web



app = Flask(__name__)
app.permanent_session_lifetime = timedelta(minutes=10)
app.secret_key = 'Set a sensible secret key here'
app.database = os.path.join(app.root_path, 'iiifauth.db')
app.config.update(dict(    
    SERVER_NAME=os.environ.get('IIIFAUTH_SERVER_NAME', None) 
))

# some globals
APP_PATH = os.path.dirname(os.path.abspath(__file__))
MEDIA_ROOT = os.path.join(APP_PATH, 'media')
AUTH_POLICY = None
with open(os.path.join(MEDIA_ROOT, 'policy.json')) as policy_data:
    AUTH_POLICY = json.load(policy_data)



@app.before_request
def func():
    """Make our sessions last longer than browser window"""
    session.permanent = True
    session.modified = True


def resolve(identifier):
    """Resolves a iiif identifier to the resource's path on disk."""
    return os.path.join(MEDIA_ROOT, identifier)


@app.route('/')
def index():
    """List all the info.jsons we have"""
    files = os.listdir(MEDIA_ROOT)
    manifests = sorted(''.join(f.split('.')[:-2]) for f in files if f.endswith('manifest.json'))
    return render_template('index.html', images=get_image_list(), manifests=manifests)


@app.route('/index.json')
def index_json():
    """JSON version of image list"""
    images = get_image_list()
    images_as_dicts = [img._asdict() for img in images]
    for img in images_as_dicts:
        img['id'] = url_for('image_id', identifier=img['id'], _external=True)
        img['label'] = img['label'].replace('{server}', url_for('index', _external=True))
    return make_acao_response(jsonify(images_as_dicts))


def get_image_list():
    """Gather the available images with their labels from the policy doc"""
    files = os.listdir(MEDIA_ROOT)
    names = sorted(f for f in files if not f.endswith('json') and not f.startswith('manifest'))
    image_nt = namedtuple('Image', ['id', 'label'])
    images = [image_nt(name, AUTH_POLICY[name]['label']) for name in names]
    return images


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
    degraded_for = policy.get('degraded_for', None)
    if degraded_for:
        identifier = degraded_for
        policy = AUTH_POLICY[degraded_for]

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

    service_id = None
    match = re.search('Bearer (.*)', request.headers.get('Authorization', ''))
    if match:
        token = match.group(1)
        print('token %s found' % token)
        db_token = query_db('select * from tokens where token=?',
                            [token], one=True)
        if db_token:
            service_id = db_token['service_id']
            print('service_id %s found' % service_id)
    else:
        print('no Authorization header found')

    if not service_id:
        print('requires access control and no service_id found')
        return False

    # Now make sure the token is for one of this image's services
    services = policy.get('auth_services', [])
    identifier_slug = 'shared' if policy.get('shared', False) else identifier
    for service in services:
        pattern = get_pattern_name(service)
        test_service_id = get_service_id(pattern, identifier_slug)
        if service_id == test_service_id:
            print('User has access to service', service_id, ' - request authorised')
            return True

    print('info request is NOT authorised')
    return False

def get_session_id():
    """Helper for session_id"""
    return session.get('session_id', None)

def authorise_resource_request(identifier):
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
        test_service_id = get_service_id(pattern, identifier_slug)
        if session.get(test_service_id, None):
            # we stored the user's access to this service in the session.
            # There will also be a row in the tokens table, but we don't need that
            # This is an example implementation, there are many ways to do this.
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
        redirect_to = "%simg/%s/info.json" % (request.url_root, degraded_version)
        print('a degraded version is available at', redirect_to)
        return make_acao_response(redirect(redirect_to, code=302))

    return make_acao_response(jsonify(info), 401)




@app.route('/img/<identifier>/<region>/<size>/<rotation>/<quality>.<fmt>')
def image_api_request(identifier, **kwargs):
    """
        A IIIF Image API request; use iiif2 to generate the tile
    """
    if authorise_resource_request(identifier):
        params = web.Parse.params(identifier, **kwargs)
        tile = iiif.IIIF.render(resolve(identifier), **params)
        return send_file(tile, mimetype=tile.mime)

    return make_response("Not authorised", 401)


@app.route('/auth/cookie/<pattern>/<identifier>', methods=['GET', 'POST'])
def cookie_service(pattern, identifier):
    """Cookie service (might be a login interaction pattern. Doesn't have to be)"""
    origin = request.args.get('origin')
    if origin is None:
        # http://iiif.io/api/auth/1.0/#interaction-with-the-access-cookie-service
        return make_response("Error - no origin supplied", 400)

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
    if authorise_resource_request(identifier):
        return successful_login(pattern, identifier, origin)

    error = None
    if identifier != 'shared':
        policy = AUTH_POLICY.get(identifier, None)
        if not policy:
            error = "No cookie service for %s" % identifier

    if not error and request.method == 'POST':
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


@app.route('/external-cookie/<identifier>', methods=['GET', 'POST'])
def external(identifier):
    """This is a 'secret' login page"""
    return handle_login('external', identifier, None, 'external.html')


def make_session(pattern, identifier, origin):
    """
        Establish a session for this user and this resource.
        This is not a production application.
    """
    # Get or create a session ID to keep track of this user's permissions
    session_id = get_session_id()
    if session_id is None:
        session_id = uuid.uuid4().hex
        session['session_id'] = session_id
    print("This user's session is", session_id)

    if origin is None:
        origin = "[No origin supplied]"
    service_id = get_service_id(pattern, identifier)
    print('User authed for service ', service_id)
    print('origin is ', origin)
    # The token can be anything, but you shouldn't be able to
    # deduce the cookie value from the token value.
    # In this demo the client cookie is a Flask session cookie,
    # we're not setting an explicit IIIF auth cookie.

    # Store the fact that user can access this service in the session
    session[service_id] = True
    # Now store a token associated that represents the user's access to this service
    token = uuid.uuid4().hex
    print('minted token:', token)
    print('session id:', session_id)

    database = get_db()
    database.execute("delete from tokens where session_id=? and service_id=?",
                     [session_id, service_id])
    database.commit()
    database.execute("insert into tokens (session_id, service_id, token, origin, created) "
                     "values (?, ?, ?, ?, datetime('now'))",
                     [session_id, service_id, token, origin])
    database.commit()


def get_service_id(pattern, identifier):
    """
        Simple format for session keys used to maintain session
    """
    return "cookie/%s/%s" % (pattern, identifier)


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
    service_id = get_service_id(pattern, identifier)
    session_id = get_session_id()
    token_object = None
    db_token = None
    print("looking for token for session %s, service %s, pattern %s" % (session_id, service_id, pattern))
    if session_id:
        db_token = query_db('select * from tokens where session_id=? and service_id=?',
                            [session_id, service_id], one=True)
    if db_token:
        print("found token %s" % db_token['token'])
        session_origin = db_token['origin']
        if origin == session_origin or pattern == 'external':
            # don't enforce origin on external auth
            token_object = {
                "accessToken": db_token['token'],
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
    service_id = get_service_id(pattern, identifier)
    session.pop('service_id')
    database = get_db()
    database.execute('delete from tokens where session_id=? and service_id=?',
                     [get_session_id(), service_id])
    database.commit()
    return "You are now logged out"


# Database to hold map of sessions to tokens issued
# you can't access the session object in an info.json request, because no credentials supplied


@app.route('/sessiontokens')
def view_session_tokens():
    """concession to admin dashboard"""
    database = get_db()
    database.execute("delete from tokens where created < date('now','-1 day')")
    database.commit()
    session_tokens = query_db('select * from tokens order by created desc')
    return render_template('session_tokens.html',
                           session_tokens=session_tokens,
                           user_session=get_session_id())

@app.route('/killsessions')
def kill_sessions():
    """Clear up all my current session tokens"""
    session_id = get_session_id()
    if session_id:
        database = get_db()
        database.execute("delete from tokens where session_id=?", [session_id])
        database.commit()
        for key in list(session.keys()):
            if key != 'session_id':
                session.pop(key, None)

    return redirect(url_for('view_session_tokens'))


def connect_db():
    """Connects to the specific database."""
    conn = sqlite3.connect(app.database)
    conn.row_factory = sqlite3.Row
    return conn


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
 