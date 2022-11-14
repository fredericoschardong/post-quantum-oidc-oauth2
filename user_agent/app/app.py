import ssl
import os
import logging
import statistics
import csv
import urllib.request
import urllib.parse
import requests

import urllib3

urllib3.disable_warnings(urllib3.exceptions.SecurityWarning)

from bs4 import BeautifulSoup
from time import sleep, perf_counter

TLS_SIGN = os.getenv("TLS_SIGN").lower()
method = "https" if TLS_SIGN else "http"
JWT_SIGN = os.getenv("JWT_SIGN").lower()
RP_IP = os.getenv("RP_IP") or "rp"
OP_IP = os.getenv("OP_IP") or "op"
DELAY_START = float(os.getenv("DELAY_START") or 1)
DELAY_BETWEEN = float(os.getenv("DELAY_BETWEEN") or 0.01)
TIMEOUT = float(os.getenv("TIMEOUT") or 10)
REPEAT = int(os.getenv("REPEAT") or 1)
LOG_LEVEL = os.getenv("LOG_LEVEL") or "CRITICAL"
TEST = os.getenv("TEST") or "all"
SAVE_TLS_DEBUG = os.getenv("SAVE_TLS_DEBUG") or True

logger = logging.getLogger("werkzeug")
logger.setLevel(level=LOG_LEVEL)

logging.basicConfig(level=LOG_LEVEL)
logger = logging.getLogger(__name__)

# SPHICS 256 require us to change this limit
import http.client

http.client._MAXLINE = 6553600

if TLS_SIGN not in ["rsa", "ecdsa"]:
    os.environ["TLS_DEFAULT_GROUPS"] = "kyber512"


def get_css_js(page, url, verify):
    ua_responses_size = 0
    soup = BeautifulSoup(page, features="html.parser")

    for link in soup.findAll("script"):
        src = urllib.parse.urljoin(url, link["src"])
        response = requests.get(src, verify=verify, timeout=TIMEOUT)
        ua_responses_size += len(response.content)

    for link in soup.findAll("link"):
        href = urllib.parse.urljoin(url, link["href"])
        response = requests.get(href, verify=verify, timeout=TIMEOUT)
        ua_responses_size += len(response.content)

    return ua_responses_size


def run_single_test():
    ua_responses_size = 0

    sleep(DELAY_BETWEEN)

    tic = perf_counter()

    if TEST == "all":
        try:
            # home
            response = requests.get(
                f"{method}://{RP_IP}/",
                verify=f"/rp_certs/IntermediaryCAs/bundlecerts_chain_rp_{TLS_SIGN}.crt",
                timeout=TIMEOUT,
            )
            ua_responses_size = len(response.content)
            ua_responses_size += get_css_js(
                response.content,
                response.url,
                verify=f"/rp_certs/IntermediaryCAs/bundlecerts_chain_rp_{TLS_SIGN}.crt",
            )

            # authenticate
            response = requests.get(
                f"{method}://{RP_IP}/auth",
                verify=f"/rp_certs/IntermediaryCAs/bundlecerts_chain_rp_{TLS_SIGN}.crt",
                allow_redirects=False,
                timeout=TIMEOUT,
            )
            response = requests.get(
                response.headers["Location"],
                verify=f"/op_certs/IntermediaryCAs/bundlecerts_chain_op_{TLS_SIGN}.crt",
                timeout=TIMEOUT,
            )
            ua_responses_size += len(response.content)
            ua_responses_size += get_css_js(
                response.content,
                response.url,
                verify=f"/op_certs/IntermediaryCAs/bundlecerts_chain_op_{TLS_SIGN}.crt",
            )

            data = {"username": "anything", "password": "anything"}

            response = requests.post(
                response.url,
                verify=f"/op_certs/IntermediaryCAs/bundlecerts_chain_op_{TLS_SIGN}.crt",
                allow_redirects=False,
                data=data,
            )
            response = requests.get(
                response.headers["Location"],
                verify=f"/rp_certs/IntermediaryCAs/bundlecerts_chain_rp_{TLS_SIGN}.crt",
                timeout=TIMEOUT,
            )
            ua_responses_size += get_css_js(
                response.content,
                response.url,
                verify=f"/rp_certs/IntermediaryCAs/bundlecerts_chain_rp_{TLS_SIGN}.crt",
            )

            # logout
            soup = BeautifulSoup(response.content, features="html.parser")
            id_token_hint = soup.find("input", {"name": "id_token_hint"}).get("value")
            post_logout_redirect_uri = soup.find(
                "input", {"name": "post_logout_redirect_uri"}
            ).get("value")

            data = {
                "id_token_hint": id_token_hint,
                "post_logout_redirect_uri": post_logout_redirect_uri,
            }

            response = requests.post(
                f"{method}://{RP_IP}/auth/logout",
                verify=f"/rp_certs/IntermediaryCAs/bundlecerts_chain_rp_{TLS_SIGN}.crt",
                data=data,
                allow_redirects=False,
                timeout=TIMEOUT,
            )
            response = requests.post(
                response.headers["Location"],
                data=data,
                verify=f"/op_certs/IntermediaryCAs/bundlecerts_chain_op_{TLS_SIGN}.crt",
                allow_redirects=False,
                timeout=TIMEOUT,
            )

            response = requests.get(
                response.headers["Location"],
                verify=f"/rp_certs/IntermediaryCAs/bundlecerts_chain_rp_{TLS_SIGN}.crt",
                allow_redirects=False,
                timeout=TIMEOUT,
            )
            ua_responses_size += len(response.content)
            ua_responses_size += get_css_js(
                response.content,
                response.url,
                verify=f"/rp_certs/IntermediaryCAs/bundlecerts_chain_rp_{TLS_SIGN}.crt",
            )

            toc = perf_counter()

            # reload RP for each test so that it GETs the /.well-known/ and /certs URLs
            # no need to reload the OP because we zero the metrics with the GET /get_requests_length
            requests.get(
                f"{method}://{RP_IP}/reload?JWT_SIGN={JWT_SIGN}",
                verify=f"/rp_certs/IntermediaryCAs/bundlecerts_chain_rp_{TLS_SIGN}.crt",
                timeout=TIMEOUT,
            )

            op_responses_size = requests.get(
                f"{method}://{OP_IP}:8080/get_requests_length",
                verify=f"/op_certs/IntermediaryCAs/bundlecerts_chain_op_{TLS_SIGN}.crt",
                timeout=TIMEOUT,
            ).json()

            return dict(
                {
                    "Tempo total": toc - tic,
                    "Req/sec": 21 / (toc - tic),
                    "Tamanho total": ua_responses_size
                    + sum(op_responses_size.values()),
                },
                **op_responses_size,
            )

        except Exception as e:
            logging.exception("Got exception on main handler")

            try:
                requests.get(
                    f"{method}://{RP_IP}/reload?JWT_SIGN={JWT_SIGN}",
                    verify=f"/rp_certs/IntermediaryCAs/bundlecerts_chain_rp_{TLS_SIGN}.crt",
                    timeout=TIMEOUT,
                )
                requests.get(
                    f"{method}://{OP_IP}:8080/get_requests_length",
                    verify=f"/op_certs/IntermediaryCAs/bundlecerts_chain_op_{TLS_SIGN}.crt",
                    timeout=TIMEOUT,
                )
            except Exception as e:
                pass

            return run_single_test()

    elif TEST == "token":
        try:
            response = requests.post(
                f"{method}://{OP_IP}:8080/protocol/openid-connect/token",
                verify=f"/op_certs/IntermediaryCAs/bundlecerts_chain_op_{TLS_SIGN}.crt",
                timeout=TIMEOUT,
            )
            ua_responses_size = len(response.content)

            toc = perf_counter()

            return {
                "Tempo total": toc - tic,
                "Req/sec": 1 / (toc - tic),
                "Tamanho total": ua_responses_size,
            }
        except Exception as e:
            logger.critical("\nTimeout!!!\n")

            return run_single_test()


if TLS_SIGN:
    keylog_filename = f"/app/tls_debug/TLS={TLS_SIGN}.tls_debug"

    if os.path.exists(keylog_filename):
        os.remove(keylog_filename)

    os.environ["SSLKEYLOGFILE"] = keylog_filename

timings = []
req_sec = []
resp_size = []
results = []

detailed_log_file = f"/app/logs/detailed/TEST={TEST} RP={RP_IP} OP={OP_IP} TLS={TLS_SIGN} JWT={JWT_SIGN} REPEAT={REPEAT}.csv"
resumed_log_file = f"/app/logs/resumed_TEST={TEST}.csv"

logger.info("Starting %d test(s) in %d seconds." % (REPEAT, DELAY_START))
sleep(DELAY_START)

with open(detailed_log_file, "w") as myfile:
    for i in range(REPEAT):
        results.append(run_single_test())
        timings.append(results[-1]["Tempo total"])
        req_sec.append(results[-1]["Req/sec"])
        resp_size.append(results[-1]["Tamanho total"])

        logger.info(f"Finished test {i} of {REPEAT}")

        wr = csv.writer(myfile)

        if i == 0:
            wr.writerow(results[0].keys())

        wr.writerow(results[-1].values())

print(f"Storing detailed logs (times + sizes) on {detailed_log_file}")
print(f"Storing resumed logs (times + sizes) on {resumed_log_file}")

print("Min time:\t %f" % min(timings))
print("Max time:\t %f" % max(timings))
print("Mean time:\t %f" % statistics.mean(timings))

if REPEAT > 1:
    print("Stdev time:\t %f\n" % statistics.stdev(timings))

print("Mean req/sec:\t %f" % statistics.mean(req_sec))

if REPEAT > 1:
    print("Stdev req/sec:\t %f\n" % statistics.stdev(req_sec))

print("Mean resp size:\t %f" % statistics.mean(resp_size))

if REPEAT > 1:
    print("Stdev resp size: %f" % statistics.stdev(resp_size))

resumed_file_exists = os.path.isfile(resumed_log_file)

with open(resumed_log_file, "a+") as myfile:
    wr = csv.writer(myfile)

    if not resumed_file_exists:
        wr.writerow(
            [
                "RP_IP",
                "OP_IP",
                "TLS",
                "JWT",
                "REPEAT",
                "Mean time",
                "Stdev time",
                "Mean req/sec",
                "Stdev req/sec",
                "Tamanho total resposta",
            ]
        )

    wr.writerow(
        [
            RP_IP,
            OP_IP,
            TLS_SIGN,
            JWT_SIGN,
            REPEAT,
            statistics.mean(timings),
            statistics.stdev(timings) if REPEAT > 1 else 0,
            statistics.mean(req_sec),
            statistics.stdev(req_sec) if REPEAT > 1 else 0,
            statistics.mean(req_sec),
            statistics.mean(resp_size),
        ]
    )
