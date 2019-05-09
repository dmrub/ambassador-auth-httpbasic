# Copyright 2018 Datawire Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from base64 import b64encode
from flask import Flask, request, Response
from functools import wraps
from pathlib import Path
from hashlib import sha256
from werkzeug.routing import Rule

import bcrypt
import logging
import os
import threading
import yaml
import time

app = Flask(__name__)
app.secret_key = os.urandom(16)

# Specify the /extauth route here because Flask requires manual specification of all the HTTP methods on the @app.route
# decorator which is tedious and prone to break in practice from new or custom HTTP methods being introduced.
app.url_map.add(Rule("/extauth", strict_slashes=False, endpoint="handle_authorization", defaults={"path": ""}))
app.url_map.add(Rule("/extauth/<path:path>", endpoint="handle_authorization"))

remote_header = os.getenv("AMBASSADOR_AUTH_REMOTE_HEADER", "")
users_file = Path(os.getenv("AMBASSADOR_AUTH_USERS_FILE", "/var/lib/ambassador/auth-httpbasic/users.yaml"))
users = {}
users_last_modified_time = 0
users_lock = threading.Lock()
auth_cache = {}


def load_users():
    global users, users_last_modified_time, users_lock

    try:
        modified_time = os.stat(str(users_file), follow_symlinks=True).st_mtime_ns
        if modified_time > users_last_modified_time:
            app.logger.info("Started loading users file from filesystem")
            modified_users = yaml.load(users_file.read_text(encoding="UTF-8"))

            with users_lock:
                users = modified_users
                users_last_modified_time = modified_time

                # store new timestamp, this will be used for invalidating cache
                ts = time.time()
                for user, user_data in users.items():
                    user_data['ts'] = ts

            auth_cache.clear()

            app.logger.info("Completed loading users file from filesystem")
        else:
            app.logger.debug(
                "Skipped loading users file from filesystem because modified time is same (old: %s, latest: %s)",
                users_last_modified_time, modified_time)
    except FileNotFoundError:
        app.logger.exception("Failed loading users file because the file was not found: %s", users_file)
    except yaml.YAMLError as e:
        app.logger.exception("Failed loading users file because the YAML is invalid")

    th = threading.Timer(5.0, load_users)
    th.daemon = True
    th.start()


def check_auth(username, password):
    with users_lock:
        user_data = users.get(username, None)
    if user_data:
        user_ts = user_data.get('ts')

        # Passwords in the users database are stored as base64 encoded sha256 to work around the fact bcrypt only
        # supports a maximum password length of 72 characters (yes that is very long). See the below link for more
        # detail.
        #
        # see "Maximum Password Length" -> https://pypi.python.org/pypi/bcrypt/3.1.0

        app.logger.info("Check authentication for user '%s'", username)

        password_key = sha256('{}:{}'.format(user_ts, password).encode("UTF-8")).hexdigest()
        if auth_cache.get((username, password_key), False):
            app.logger.info("User '%s' is already authenticated", username)
            return True

        password_hexdigest = sha256(password.encode("UTF-8")).hexdigest()
        sha256_password = password_hexdigest.encode("UTF-8")
        prepared_password = b64encode(sha256_password)

        result = bcrypt.checkpw(prepared_password, user_data.get("hashed_password", "").encode("UTF-8"))
        if result:
            app.logger.info("User '%s' is authenticated", username)
            auth_cache[(username, password_key)] = True

        return result
    else:
        return False


def unauthorized():
    return Response(status=401, headers={"WWW-Authenticate": 'Basic realm="Authentication Required"'})


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Favicon is the little icon associated with a domain in a web browser. Browsers issue a request for the
        # resource /favicon.ico alongside any other HTTP request which pollutes the logs with lots of 404 Not Found logs
        # because usually the favicon cannot be resolved. This tells the browser to go away; there is no favicon here.
        if request.path == "/favicon.ico":
            return Response(status=403)

        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return unauthorized()

        return f(*args, **kwargs)

    return decorated


@app.errorhandler(404)
def not_found(e):
    return Response(status=404)


@app.route("/readyz", methods=["GET"])
def readyz():
    return "OK", 200


@app.route("/healthz", methods=["GET"])
def healthz():
    return "OK", 200


@app.endpoint("handle_authorization")
@requires_auth
def handle_authorization(path):
    headers = None
    if remote_header:
        headers = {remote_header: request.authorization.username}
    return Response(status=200, headers=headers)


@app.before_first_request
def setup():
    if not app.debug:
        app.logger.addHandler(logging.StreamHandler())
        app.logger.setLevel(logging.INFO)

    load_users()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
