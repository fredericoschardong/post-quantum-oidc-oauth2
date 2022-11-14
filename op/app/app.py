# Author: Frederico Schardong and Fernanda Müller
import os
import ssl
import sys
import json
import logging
import secrets

from oic.utils.time_util import utc_time_sans_frac
from oic.utils.keyio import build_keyjar
from oic.utils.jwt import JWT
from utils.utils import get_openid_configuration

from flask import Flask, flash, jsonify, redirect, render_template, url_for, request, g
from werkzeug.serving import run_simple

# SPHICS 256 require us to change this limit
import http.client

http.client._MAXLINE = 6553600

# disable Flask's message on startup
import flask.cli

flask.cli.show_server_banner = lambda *args: None

TLS_SIGN = (os.getenv("TLS_SIGN") or "").lower()
JWT_SIGN = (os.getenv("JWT_SIGN") or "").lower() or "rsa"

OP_IP = os.getenv("OP_IP") or "op"
RP_IP = os.getenv("RP_IP") or "rp"
LOG_LEVEL = os.getenv("LOG_LEVEL") or "CRITICAL"
SAVE_TLS_DEBUG = os.getenv("SAVE_TLS_DEBUG") or True

logger = logging.getLogger("werkzeug")
logger.setLevel(level=LOG_LEVEL)

logging.basicConfig(level=LOG_LEVEL)
logger = logging.getLogger(__name__)

ARG2OQS = {
    "dilithium2": "Dilithium2",
    "dilithium3": "Dilithium3",
    "dilithium5": "Dilithium5",
    "falcon512": "Falcon-512",
    "falcon1024": "Falcon-1024",
    "sphincsshake256128fsimple": "SPHINCS+-SHAKE256-128f-simple",
    "sphincsshake256192fsimple": "SPHINCS+-SHAKE256-192f-simple",
    "sphincsshake256256fsimple": "SPHINCS+-SHAKE256-256f-simple",
}

sub = "0b58dd50-2abc-4a2b-a20b-c405b050e98f"


def set_global_constants(tls_sign, jwt_sign):
    global TLS_SIGN, JWT_SIGN, METHOD, KEY_TYPE, KEYJAR, SERVER_ADDRESS

    TLS_SIGN = tls_sign if tls_sign else TLS_SIGN
    JWT_SIGN = jwt_sign if jwt_sign else JWT_SIGN

    if TLS_SIGN not in ["rsa", "ecdsa"]:
        os.environ["TLS_DEFAULT_GROUPS"] = "kyber512"

    METHOD = "https" if TLS_SIGN else "http"
    SERVER_ADDRESS = f"{METHOD}://{OP_IP}:8080/"

    KEY_TYPE = "PQC" if JWT_SIGN not in ["rsa", "ecdsa"] else JWT_SIGN.upper()

    if KEY_TYPE == "PQC":
        _, KEYJAR, _ = build_keyjar(
            [{"type": "PQC", "alg": ARG2OQS[JWT_SIGN], "use": ["sig"]}]
        )
    elif JWT_SIGN == "rsa":
        _, KEYJAR, _ = build_keyjar(
            [
                {
                    "type": "CryptographyRSA",
                    "alg": "CryptographyRSA",
                    "key": f"/op_certs/JWTKeys/op_rsa.key",
                    "use": ["sig"],
                }
            ]
        )
    else:
        _, KEYJAR, _ = build_keyjar(
            [
                {
                    "type": "CryptographyECDSA",
                    "alg": "CryptographyECDSA",
                    "key": "",
                    "use": ["sig"],
                }
            ]
        )


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


REQUEST_LENGTH = {}


def get_app():
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

    @app.before_request
    def gather_request_data():
        g.path = request.path

    @app.after_request
    def test(response):
        key = g.path.split("/")[-1]

        if key != "get_requests_length" and ".css" not in key and ".js" not in key:
            key = "Total response size for the OP request: " + key
            REQUEST_LENGTH[key] = REQUEST_LENGTH.get(key, 0) + int(
                response.content_length or 0
            )

        return response

    @app.route("/.well-known/openid-configuration", methods=["GET"])
    def auth_realms_post_quantum():
        return jsonify(json.loads(get_openid_configuration(METHOD, OP_IP)))

    @app.route("/protocol/openid-connect/auth", methods=["GET"])
    def idp_pqc_auth_get():
        state = request.args.get("state")

        return render_template("auth.html", state=state)

    @app.route("/protocol/openid-connect/auth", methods=["POST"])
    def idp_pqc_auth_post():
        state = request.form.get("state") or request.args.get("state")
        session_state = "a6480a0f-bb38-4c7a-9908-20f8608e1e48"
        code = "a34b69e9-39af-4301-bf75-de6badb92823.a6480a0f-bb38-4c7a-9908-20f8608e1e48.39fecc"

        return redirect(
            f"{METHOD}://{RP_IP}/auth/callback?state={state}&session_state={session_state}&code={code}",
            code=307,
        )

    @app.route("/protocol/openid-connect/token", methods=["GET", "POST"])
    def idp_pqc_token():
        # https://github.com/pallets/flask/issues/4507#issuecomment-1082795525
        request.data

        iss = SERVER_ADDRESS
        token_type = "Bearer"
        session_state = secrets.token_urlsafe()
        exp = utc_time_sans_frac() + 100000

        if KEY_TYPE == "PQC":
            sign_alg = ARG2OQS[JWT_SIGN]
        elif JWT_SIGN == "rsa":
            sign_alg = "CryptographyRSA"
        else:
            sign_alg = "CryptographyECDSA"

        kid = KEYJAR.get("sig")[0].kid

        access_token = JWT(KEYJAR, sign_alg=sign_alg).pack(
            kid=kid,
            iss=iss,
            sub=sub,
            aud="account",
            exp=exp,
            typ=token_type,
            nonce=secrets.token_urlsafe(),
            session_state=session_state,
            iat=utc_time_sans_frac(),
        )

        refresh_token = JWT(KEYJAR, sign_alg=sign_alg).pack(
            kid=kid,
            iss=iss,
            sub=sub,
            aud="account",
            exp=exp * 2,
            typ="refresh_token",
            nonce=secrets.token_urlsafe(),
            session_state=session_state,
            iat=utc_time_sans_frac(),
        )

        id_token = JWT(KEYJAR, sign_alg=sign_alg).pack(
            kid=kid, iss=iss, sub=sub, aud="python", exp=exp, iat=utc_time_sans_frac()
        )

        session_state = ""

        return {
            "access_token": access_token,
            "expires_in": 3656500,
            "refresh_expires_in": 18546400,
            "refresh_token": refresh_token,
            "token_type": token_type,
            "id_token": id_token,
            "not-before-policy": 0,
            "session_state": session_state,
            "scope": "openid email profile",
        }

    @app.route("/protocol/openid-connect/certs", methods=["GET"])
    def idp_pqc_certs():
        return {"keys": KEYJAR.dump_issuer_keys("")}

    @app.route("/protocol/openid-connect/userinfo", methods=["POST"])
    def idp_pqc_userinfos():
        access_token = request.args.get("access_token") or request.form.get(
            "access_token"
        )

        return {
            "sub": sub,
            "email_verifield": False,
            "name": "Fernanda Larissa Müller",
            "preferred_name": "teste",
            "given_name": "Fernanda",
            "family_name": "Muller",
            "email": "teste@gmail",
        }

    @app.route("/protocol/openid-connect/logout", methods=["POST"])
    def idp_pqc_logout():
        return redirect(
            request.args.get("post_logout_redirect_uri")
            or request.form.get("post_logout_redirect_uri")
        )

    @app.route("/get_requests_length", methods=["GET"])
    def get_requests_length():
        global REQUEST_LENGTH

        _REQUEST_LENGTH = dict(REQUEST_LENGTH)
        REQUEST_LENGTH = {}

        return _REQUEST_LENGTH

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
            certfile=f"/op_certs/ServerCerts/bundlecerts_chain_op_{TLS_SIGN}_{OP_IP}.crt",
            keyfile=f"/op_certs/ServerCerts/op_{TLS_SIGN}_{OP_IP}.key",
        )

        if SAVE_TLS_DEBUG:
            sslContext.keylog_filename = keylog_filename
    else:
        sslContext = None

    run_simple("0.0.0.0", 8080, AppReloader(get_app), ssl_context=sslContext)
