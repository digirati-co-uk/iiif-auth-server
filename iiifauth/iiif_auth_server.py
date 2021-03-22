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
    SERVER_NAME=os.environ.get('IIIFAUTH_SERVER_NAME', None),
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True
))

# some globals
APP_PATH = os.path.dirname(os.path.abspath(__file__))
MEDIA_ROOT = os.path.join(APP_PATH, 'media')
with open(os.path.join(MEDIA_ROOT, 'media_auth_config.json')) as auth_config_file:
    MEDIA_AUTH_CONFIG = json.load(auth_config_file)


@app.before_request
def func():
    """Make our Flask sessions last longer than the browser window lifetime"""
    session.permanent = True
    session.modified = True


def resolve(identifier):
    """Resolves a iiif identifier to the resource's path on disk."""
    return os.path.join(MEDIA_ROOT, identifier)


@app.route('/')
def index():
    """List all the authed resources we have, and where available, manifests that refer to them"""
    files = os.listdir(MEDIA_ROOT)
    manifests = sorted(''.join(f.split('.')[:-2]) for f in files if f.endswith('manifest.json'))
    return render_template('index.html', images=get_media_summaries(), manifests=manifests)


def get_media_summaries():
    media_as_dicts = [media._asdict() for media in get_media_list()]
    for media in media_as_dicts:
        media_id = media['id']
        media["display"] = media_id
        if media['type'] != 'ImageService2':
            # this is not a service; it's the resource itself
            assert_auth_services(media, media_id, True)
            media['partOf'] = url_for('manifest', identifier=media_id[:-4], _external=True)
            media['type'] = get_dc_type(media_id)
            media['id'] = url_for('resource_request', identifier=media_id, _external=True)
        else:
            media['id'] = url_for('image_id', identifier=media_id, _external=True)
        media['label'] = media['label'].replace('{server}', url_for('index', _external=True))
        if media.get("format", None) is None:
            del media["format"]
    return media_as_dicts


def get_dc_type(filename):
    extension = filename.split('.')[-1]
    if extension == "mp4":
        return "Video"
    if extension == "mp3" or extension == "mpd":
        return "Audio"
    if extension == "pdf":
        return "Text"
    if extension == "gltf":
        return "PhysicalObject"
    return "Unknown"


@app.route('/index.json')
def index_json():
    """JSON version of media list"""
    return make_acao_response(jsonify(get_media_summaries()), 200, True)


def get_media_list():
    """Gather the available media (i.e., content resources) with their labels from the auth config doc"""
    files = list_files(MEDIA_ROOT)
    media_names = sorted(f for f in files if not f.endswith('json') and not f.startswith('manifest'))
    media_nt = namedtuple('Image', ['id', 'label', 'type', 'format'])
    media = [media_nt(
        media_name,
        MEDIA_AUTH_CONFIG[media_name]['label'],
        MEDIA_AUTH_CONFIG[media_name].get('type', 'ImageService2'),
        MEDIA_AUTH_CONFIG[media_name].get('format', None)
    ) for media_name in media_names]

    return media


def list_files(path):
    for file in os.listdir(path):
        if os.path.isfile(os.path.join(path, file)):
            yield file


def make_manifest(identifier):
    """
        Transform skeleton manifest into one with sensible URLs
        For this demo, any jpgs will be turned into image services with auth services
        as described in the policy.json document.
        To demo non-service auth, use a different file extension.
    """
    with open(os.path.join(MEDIA_ROOT, f"{identifier}.manifest.json")) as source_manifest:
        new_manifest = json.load(source_manifest)
        manifest_id = f"{request.url_root}manifest/{identifier}"

        canvases = new_manifest.get("items", None)
        if canvases is not None:
            new_manifest['id'] = manifest_id
        else:
            new_manifest['@id'] = manifest_id
            new_manifest['sequences'][0]['@id'] = (
                f"{request.url_root}manifest/{identifier}/sequence")
            canvases = new_manifest['sequences'][0]['canvases']

        rendering = new_manifest.get("rendering", [])
        if len(rendering) > 0:
            # just put the auth services on the rendering for demo
            resource_identifier = rendering[0]['id']
            assert_auth_services(rendering[0], resource_identifier, True)
            rendering[0]['id'] = f"{request.url_root}resources/{resource_identifier}"
        else:
            for canvas in canvases:
                # Currently this demo uses a P2 manifest for image services
                # and a P3 manifest for non-image-service auth
                # TODO - an example of a P3 with image service
                images = canvas.get('images', [])
                if len(images) > 0:
                    # Presentation 2
                    image = canvas['images'][0]['resource']
                    image_identifier = image['@id']
                    if not image_identifier.startswith("http"):
                        canvas['images'][0]['@id'] = f"{request.url_root}image-annos/{image_identifier}"
                        image['service'] = {
                            "@context": iiifauth.terms.CONTEXT_IMAGE,
                            "@id": f"{request.url_root}img/{image_identifier}",
                            "profile": iiifauth.terms.PROFILE_IMAGE
                        }
                        image['@id'] = f"{image['service']['@id']}/full/full/0/default.jpg"
                # In order to demo non-service auth we have to add a strange hybrid of prezi3
                items = canvas.get('items', [])
                if len(items) > 0:
                    # Presentation 3
                    anno = canvas['items'][0]['items'][0]
                    resource = anno['body']
                    resource_identifier = resource['id']
                    if not resource_identifier.startswith("http"):
                        anno['id'] = f"{request.url_root}resource-annos/{resource_identifier}"
                        assert_auth_services(resource, resource_identifier, True)
                        resource['id'] = f"{request.url_root}resources/{resource_identifier}"

    return new_manifest


@app.route('/manifest/<identifier>')
def manifest(identifier):
    new_manifest = make_manifest(identifier)
    return make_acao_response(jsonify(new_manifest), 200, True)


def make_acao_response(response_object, status=None, cache=None, origin=None):
    """We're handling CORS directly for clarity"""
    resp = make_response(response_object, status)
    resp.headers['Access-Control-Allow-Origin'] = origin or '*'
    # only for MPEG-DASH:
    resp.headers['Access-Control-Allow-Credentials'] = "true"
    if cache is None:
        resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    else:
        resp.headers['Cache-Control'] = 'public, max-age=120'
    return resp


def preflight():
    """Handle a CORS preflight request"""
    resp = make_acao_response('', 200)
    resp.headers['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS, HEAD'
    resp.headers['Access-Control-Allow-Headers'] = 'Authorization'
    return resp


def get_pattern_name(service):
    """
        Get a friendly pattern name / slug from the auth service profile
    """
    return service['profile'].split('/')[-1]


def assert_auth_services(info, identifier, prezi3=False):
    """
        Augment the info.json, or other resource, with auth service(s) from our
        'database' of auth policy
    """
    original_config = MEDIA_AUTH_CONFIG[identifier]
    config = original_config
    degraded_for = original_config.get('degraded_for', None)
    if degraded_for:
        identifier = degraded_for
        config = MEDIA_AUTH_CONFIG[degraded_for]

    services = config.get('auth_services', [])

    for service in services:
        if not prezi3:
            service['@context'] = iiifauth.terms.CONTEXT_AUTH
        pattern = get_pattern_name(service)
        identifier_slug = 'shared' if config.get('shared', False) else identifier
        service['@id'] = f"{request.url_root}auth/cookie/{pattern}/{identifier_slug}"
        service['service'] = [
            {
                "@id": f"{request.url_root}auth/token/{pattern}/{identifier_slug}",
                "profile": iiifauth.terms.PROFILE_TOKEN
            },
            {
                "@id": f"{request.url_root}auth/logout/{pattern}/{identifier_slug}",
                "profile": iiifauth.terms.PROFILE_LOGOUT,
                "label": "log out"
            }
        ]

        if prezi3:
            service["@type"] = "AuthCookieService1"
            service['service'][0]['@type'] = "AuthTokenService1"
            service['service'][1]['@type'] = "AuthLogoutService1"

        if config.get("explicit_probe", False):
            service['service'].append({
                "@id": f"{request.url_root}probe/{identifier}",
                "@type": "AuthProbeService1",
                "profile": iiifauth.terms.PROFILE_PROBE,
            })

    if len(services) > 0:
        if prezi3 or len(services) > 1:
            info['service'] = services
        else:
            info['service'] = services[0]

    max_width = original_config.get('maxWidth', None)
    if max_width is not None:
        info['profile'].append({
            "maxWidth": max_width
        })


def authorise_probe_request(identifier):
    """
        Authorise info.json or probe request based on token
        This should not be used to authorise DIRECT requests for content resources
    """
    policy = MEDIA_AUTH_CONFIG[identifier]
    if policy.get('open'):
        print(f'{identifier} is open, no auth required')
        return True

    service_id = None
    match = re.search('Bearer (.*)', request.headers.get('Authorization', ''))
    if match:
        token = match.group(1)
        print(f'token {token} found')
        db_token = query_db('select * from tokens where token=?', [token], one=True)
        if db_token:
            service_id = db_token['service_id']
            print(f'service_id {service_id} found')
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
        This method should not accept a token as evidence of identity
    """
    policy = MEDIA_AUTH_CONFIG[identifier]
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


@app.route('/img/<identifier>/info.json', methods=['GET', 'OPTIONS', 'HEAD'])
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
    uri = f"{request.url_root}img/{identifier}"
    info = web.info(uri, resolve(identifier))
    assert_auth_services(info, identifier)

    if authorise_probe_request(identifier):
        return make_acao_response(jsonify(info), 200)

    print('The user is not authed for this resource')
    degraded_version = MEDIA_AUTH_CONFIG[identifier].get('degraded', None)
    if degraded_version:
        redirect_to = f"{request.url_root}img/{degraded_version}/info.json"
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
        config = MEDIA_AUTH_CONFIG[identifier]
        max_width = config.get('maxWidth', None)
        if max_width is not None:
            # for the demo, please supply width and height in the policy if max... applies
            # I could go and find it out but it will be slow for tile requests.
            full_w = config['width']
            full_h = config['height']
            req_w, req_h = get_actual_dimensions(
                params.get('region'),
                params.get('size'),
                full_w,
                full_h)
            if req_w > max_width or req_h > max_width:
                return make_response("Requested size too large, maxWidth is " + str(max_width))

        tile = iiif.IIIF.render(resolve(identifier), **params)
        return send_file(tile, mimetype=tile.mime)

    return make_response("Not authorised", 401)


def get_actual_dimensions(region, size, full_w, full_h):
    """
        TODO: iiif2 does not support !w,h syntax, or max...
        need to update it to 2.1 and !
        in the meantime I will just support this operation on w,h or w, syntax in the size slot
        and not for percent
        THIS IS NOT HOW IT SHOULD BE DONE...
    """
    if region.get('full', False):
        r_width, r_height = full_w, full_h
    else:
        r_width = region['w']
        r_height = region['h']

    if size.get('full', False):
        width, height = r_width, r_height
    else:
        width, height = size['w'], size['h']

    if width and not height:
        # scale height to width, preserving aspect ratio
        height = int(round(r_height * float(width / float(r_width))))

    elif height and not width:
        # scale to height, preserving aspect ratio
        width = int(round(float(r_width) * float(height / float(r_height))))

    print("width, height", width, height)
    return width, height


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
        policy = MEDIA_AUTH_CONFIG.get(identifier, None)
        if not policy:
            error = f"No cookie service for {identifier}"

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
    return f"cookie/{pattern}/{identifier}"


def split_key(key):
    """Get the pattern and the identifier out of the key"""
    parts = key.split('/')
    return {
        "pattern": parts[1],
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
    print(f"looking for token for session {session_id}, service {service_id}, pattern {pattern}")
    if session_id:
        db_token = query_db('select * from tokens where session_id=? and service_id=?',
                            [session_id, service_id], one=True)
    if db_token:
        print(f"found token {db_token['token']}")
        session_origin = db_token['origin']
        if origin == session_origin or pattern == 'external':
            # don't enforce origin on external auth
            token_object = {
                "accessToken": db_token['token'],
                "expiresIn": 600
            }
        else:
            print(f"session origin was {session_origin}")
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
        return render_template('token.html', token_object=json.dumps(token_object), origin=origin)

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


@app.route('/resources/<identifier>', methods=['GET', 'OPTIONS', 'HEAD'])
def resource_request(identifier):
    # This might be used as a probe
    # TODO - what happens when this is the MPEG-DASH manifest?
    print("METHOD:", request.method)
    if request.method == 'OPTIONS':
        print('CORS preflight request for', identifier)
        return preflight()

    if request.method == 'HEAD':
        if authorise_probe_request(identifier):
            return make_acao_response('', 200)
        return make_acao_response('', 401)

    policy = MEDIA_AUTH_CONFIG[identifier]
    if authorise_resource_request(identifier):
        resp = send_file(resolve(identifier))
        required_session_origin = None
        if policy.get("format", None) == "application/dash+xml":
            session_id = get_session_id()
            db_token = None
            if session_id:
                db_token = query_db('select * from tokens where session_id=?', [session_id], one=True)
            if db_token:
                print(f"found token {db_token['token']}")
                required_session_origin = db_token['origin']
                # Here we are saying it's OK to echo back the origin we acquired during
                # the auth flow, from the client.
                # This ony happens here, not generally;
                # It happens because this server needs to support adaptive bit rate formats
                # The server could validate the origin, from the request (although not tamper-proof)
                # Or by other means, including whitelists
                # THIS IS ONLY FOR non-simple content requests, and lies outside the auth spec.
                #
                # See https://github.com/IIIF/api/issues/1290#issuecomment-417924635
                #
            else:
                # BUT... the client might be making a credentialled request for
                # something that is not authed?
                required_session_origin = request.headers.get('Origin', None)
        return make_acao_response(resp, origin=required_session_origin)  # for dash.js
    else:
        degraded_version = policy.get('degraded', None)
        if degraded_version:
            content_location = f"{request.url_root}resources/{degraded_version}"
            print('a degraded version is available at', content_location)
            return redirect(content_location, code=302)

    return make_response("Not authorised", 401)


@app.route('/resources/<manifest_identifier>/<fragment>', methods=['GET'])
def resource_request_fragment(manifest_identifier, fragment):
    id_parts = manifest_identifier.split(".token.")
    if len(id_parts) == 1:
        id_parts.append(None)
    identifier, token = tuple(id_parts)
    reconstructed_path = os.path.join(manifest_identifier, fragment)
    # TODO
    # if not access controlled, just serve the fragment:
    return make_acao_response(send_file(resolve(reconstructed_path)))
    # If token is not None, authorise on that. It should be a hash of the user's sesison token
    # (for demo purposes!)
    # Otherwise, look for cookies and use them.


@app.route('/probe/<identifier>', methods=['GET', 'OPTIONS', 'HEAD'])
def probe(identifier):
    if request.method == 'OPTIONS':
        return preflight()

    policy = MEDIA_AUTH_CONFIG[identifier]
    probe_body = {
        "contentLocation": f"{request.url_root}resources/{identifier}",
        "label": "Probe service for " + identifier
    }
    http_status = 200
    if not authorise_probe_request(identifier):
        print('The user is not authed for the resource being probed via this service')
        degraded_version = policy.get('degraded', None)
        if degraded_version:
            probe_body["contentLocation"] = f"{request.url_root}resources/{degraded_version}"
        else:
            http_status = 401

    return make_acao_response(jsonify(probe_body), http_status)


if __name__ == '__main__':
    app.run(ssl_context='adhoc')
