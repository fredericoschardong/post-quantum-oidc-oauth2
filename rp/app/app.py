# Author: Frederico Schardong and Fernanda Müller
import os
import ssl
import sys
import logging
import requests

from urllib.parse import urlencode

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    url_for,
    request,
    make_response,
)
from werkzeug.serving import run_simple

from oic.oic.consumer import Consumer
from oic.utils.authn.client import ClientSecretBasic, ClientSecretPost
from oic.utils.sdb import DictSessionBackend
from oic.utils.http_util import Redirect
from oic.exception import AccessDenied
from oic.oic.provider import Provider
from oic.oic.message import EndSessionRequest
from oic.utils.keyio import KeyJar, KeyBundle

OP_IP = os.getenv("OP_IP") or "op"
RP_IP = os.getenv("RP_IP") or "rp"

LOG_LEVEL = os.getenv("LOG_LEVEL") or "CRITICAL"
logger = logging.getLogger("werkzeug")
logger.setLevel(level=LOG_LEVEL)

logging.basicConfig(level=LOG_LEVEL)
logger = logging.getLogger(__name__)

OIDC_CLIENT_ID = "python"
OIDC_CLIENT_SECRET = "40cbc260-798c-4585-8d6b-54e8418fcb05"
SESSION_SECRET_KEY = "unsafe"
TIMEOUT = float(os.getenv("TIMEOUT") or 10)
SAVE_TLS_DEBUG = os.getenv("SAVE_TLS_DEBUG") or True

TLS_SIGN = (os.getenv("TLS_SIGN") or "").lower()
JWT_SIGN = (os.getenv("JWT_SIGN") or "").lower() or "rsa"

# SPHICS 256 require us to change this limit
import http.client

http.client._MAXLINE = 6553600


def set_global_constants(tls_sign, jwt_sign):
    global TLS_SIGN, JWT_SIGN, METHOD, OIDC_SERVER_URL, SERVER_ADDRESS, KEY_TYPE

    TLS_SIGN = tls_sign if tls_sign else TLS_SIGN
    JWT_SIGN = jwt_sign if jwt_sign else JWT_SIGN

    if TLS_SIGN not in ["rsa", "ecdsa"]:
        os.environ["TLS_DEFAULT_GROUPS"] = "kyber512"

    KEY_TYPE = "PQC" if JWT_SIGN not in ["rsa", "ecdsa"] else JWT_SIGN.upper()
    KEY_TYPE = "CryptographyECDSA" if KEY_TYPE == "ecdsa" else KEY_TYPE
    KEY_TYPE = "CryptographyRSA" if KEY_TYPE == "rsa" else KEY_TYPE

    METHOD = "https" if TLS_SIGN else "http"
    OIDC_SERVER_URL = f"{METHOD}://{OP_IP}:8080/"
    SERVER_ADDRESS = f"{METHOD}://{RP_IP}:%d" % (443 if METHOD == "https" else 80)


set_global_constants(TLS_SIGN, JWT_SIGN)

# set to True to inform that the app needs to be re-created
to_reload = False


# soft and fast reloading
# took from https://gist.github.com/nguyenkims/ff0c0c52b6a15ddd16832c562f2cae1d
class AppReloader(object):
    def __init__(self, create_app):
        self.create_app = create_app
        self.app = create_app()

    def get_application(self):
        global to_reload
        if to_reload:
            self.app = self.create_app()
            to_reload = False

        return self.app

    def __call__(self, environ, start_response):
        app = self.get_application()
        return app(environ, start_response)


def get_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = SESSION_SECRET_KEY
    app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

    session = dict()

    @app.before_first_request
    def configure_rp():
        global consumer, config

        verify_ssl = (
            f"/op_certs/IntermediaryCAs/bundlecerts_chain_op_{TLS_SIGN}.crt"
            if TLS_SIGN
            else False
        )
        client_cert = (
            (
                f"/rp_certs/ServerCerts/rp_{TLS_SIGN}_{RP_IP}.crt",
                f"/rp_certs/ServerCerts/rp_{TLS_SIGN}_{RP_IP}.key",
            )
            if TLS_SIGN
            else None
        )

        keyjar = KeyJar(verify_ssl=verify_ssl)

        consumer = Consumer(
            DictSessionBackend(),
            {
                "authz_page": "/auth/callback",
                "response_type": "code",
                "timeout": TIMEOUT,
            },
            client_config={
                "client_id": OIDC_CLIENT_ID,
                "client_authn_method": {
                    "client_secret_post": ClientSecretPost,
                    "client_secret_basic": ClientSecretBasic,
                },
                "keyjar": keyjar,
                "verify_ssl": verify_ssl,
                "client_cert": client_cert,
            },
        )

        config = consumer.provider_config(OIDC_SERVER_URL)

        kb = KeyBundle(
            source=config["jwks_uri"],
            keytype=KEY_TYPE,
            keyusage="sig",
            verify_ssl=f"/op_certs/IntermediaryCAs/bundlecerts_chain_op_{TLS_SIGN}.crt",
        )

        for k in kb.keys():
            k.add_kid()

        keyjar.add_kb(OIDC_CLIENT_ID, kb)

        consumer.set_client_secret(OIDC_CLIENT_SECRET)

    @app.route("/auth", methods=["GET"])
    def auth():
        state, url = consumer.begin(
            scope="openid email",
            response_type="code",
            use_nonce=True,
            path=SERVER_ADDRESS,
        )
        session["state"] = state

        return Redirect(url)

    @app.route("/auth/callback", methods=["GET", "POST"])
    def auth_callback():
        try:
            aresp, atr, idt = consumer.parse_authz(
                query=request.query_string.decode("utf-8")
            )

            assert aresp["state"] == session["state"]

            session["access_token"] = consumer.complete(state=aresp["state"])[
                "access_token"
            ]

            flash("You have been logged in", "success")

        except AssertionError:
            flash("Error", "error")

        return redirect(url_for("index"))

    @app.route("/auth/logout", methods=["POST"])
    def logout():
        consumer.end_session()
        session.pop("state")
        session.pop("access_token")

        flash("You have been logged out")

        return make_response(
            request.data,
            307,
            {
                "Location": config["end_session_endpoint"],
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )

    @app.route("/", methods=["GET"])
    def index():
        try:
            data = consumer.get_user_info(state=session["state"])
            id_token_jwt = consumer.grant[session["state"]].get_id_token().jwt
            return render_template(
                "index.html",
                loggedIn=True,
                data=data,
                id_token_jwt=id_token_jwt,
                post_logout_redirect_uri=SERVER_ADDRESS,
            )
        except AccessDenied:
            session.pop("state")
            return render_template("index.html", loggedIn=False)
        except KeyError:
            return render_template("index.html", loggedIn=False)

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template("error.html", error="Page not found"), 404

    @app.route("/reload", methods=["GET"])
    def reload():
        set_global_constants(TLS_SIGN, request.args.get("JWT_SIGN"))
        global to_reload
        to_reload = True
        logger.info(f"\nRELOADING... now using TLS={TLS_SIGN} and JWT={JWT_SIGN}\n")
        return "ok"

    return app


if __name__ == "__main__":
    if TLS_SIGN:
        keylog_filename = f"/app/tls_debug/TLS={TLS_SIGN}.tls_debug"

        if os.path.exists(keylog_filename):
            os.remove(keylog_filename)

        sslContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        sslContext.minimum_version = ssl.TLSVersion.TLSv1_3
        sslContext.load_cert_chain(
            certfile=f"/rp_certs/ServerCerts/bundlecerts_chain_rp_{TLS_SIGN}_{RP_IP}.crt",
            keyfile=f"/rp_certs/ServerCerts/rp_{TLS_SIGN}_{RP_IP}.key",
        )

        if SAVE_TLS_DEBUG:
            sslContext.keylog_filename = keylog_filename
    else:
        sslContext = None

    run_simple(
        "0.0.0.0",
        (443 if METHOD == "https" else 80),
        AppReloader(get_app),
        ssl_context=sslContext,
    )
