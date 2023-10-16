# Post-Quantum OAuth 2.0 and OpenID Connect

This repository archives the code used in the paper [Post-Quantum Electronic Identity: Adapting OpenID Connect and OAuth 2.0 to the Post-Quantum Era](https://link.springer.com/chapter/10.1007/978-3-031-20974-1_20).

We used [docker](https://www.docker.com/) to conternize our implementation of OpenID Connect's three roles: the OpenID Connect Provider ([op](op)), Relying Party ([rp](rp)), and [User Agent](user_agent).

## Install

Run `git submodule init` and `git submodule update` to download the required submodules.

You need to have at least `docker` and `docker-compose` to run our realistic use case. If you want to reproduce the results from our paper locally (i.e. ignoring latency), you need to have `mergecap`, `gnuplot` and `traceroute`. Finally, to reproduce our tests in real-world conditions, you will need to rent Amazon EC2 instances (other vendors should work fine) and also have `ssh` installed.

## Configure

The way to set parameters for the simulations is through environment variables.

Relevant variables to keep in mind:

- `TLS_SIGN`: The signature algorithm used in the TLS handshake. The available options are ` ` (blank means no TLS), `rsa`, `ecdsa`, `dilithium2`, `dilithium3`, `dilithium5`, `falcon512`, `falcon1024`, `sphincsshake256128fsimple`, `sphincsshake256192fsimple`, and `sphincsshake256256fsimple`. Defaults to `rsa`;
- `JWT_SIGN`: The signature algorithm used to sign the `access token`, `refresh_token` and the `ID token`. The available options are `rsa`, `ecdsa`, `dilithium2`, `dilithium3`, `dilithium5`, `falcon512`, `falcon1024`, `sphincsshake256128fsimple`, `sphincsshake256192fsimple`, and `sphincsshake256256fsimple`. Defaults to `rsa`;
- `OP_IP`: The IP address of the OpenID Connect Provider. Defaults to `op` (the container name);
- `RP_IP`: The IP address of the Relying Party (i.e. the client as per the OAuth 2 nomenclature). Defaults to `rp`;
- `REPEAT`: The number of times the test will be repeated. If it is `> 1`, then an extra test is added as a cold start and its timing is removed from the result set. Defaults to `1`;

Less relevant variables:

- `SUBJECT_ALT_NAME_TYPE`: x509 stuff, default value is `DNS`. In local tests we need to use `DNS` because we use hostnames `op` and `rp`, which are not valid IP addresses;
- `LOG_LEVEL`: The amount of stuff you will see. Options are `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. Defaults to `CRITICAL` (i.e. not showing anything);
- `DELAY_START`: The delay in seconds before starting the first test. Defaults to 1 second;
- `DELAY_BETWEEN`: The delay in seconds to check if the RP and OP are running. Defaults to `0.01` (because `0.001` changes nothing as far as I could test and `0.1` adds delay);
- `TIMEOUT`: timeout for any request made by `user_agent` and `rp`. Defaults to `10`.
- `SAVE_TLS_DEBUG`: `true` if you want to save the file to decrypt TLS communication. The file is stored at `user_agent/app/tls_debug/user_agent.tls_debug` and `results/*/*/tls_debug/user_agent.tls_debug`. Defaults to `true`.

## Running

### Local

Run the following to repeat our use case ten times, using RSA for the JWT and no TLS:

```console
TLS_SIGN= JWT_SIGN=rsa REPEAT=10 docker-compose up --exit-code-from user_agent op rp user_agent
```

It produces the raw performance numbers regarding time and size, which you can find at `user_agent/app/logs/`. 

We created a script to automate a large portion of the emphirical evaluation. You can reproduce the experiments from our paper locally (i.e. ignoring latency) with:

```console
./run_experiments.sh
```

### Remote

If you want to run in a realistic environment, then start two Amazon EC2 instances.

There are extra variables for remote installation and execution, they are:

- `AMAZON_PEM_FILE`: env variable pointing to the localtion of the .pem file downloaded from Amazon EC2 to SSH into the machines;
- `AMAZON_USER`: as the name suggests.

Then run the following to install everything is needed on your EC2 instances (adjust the IP addresses accordingly):

```console
OP_IP=54.209.156.87 RP_IP=54.87.166.113 AMAZON_PEM_FILE=~/<your pem file>.pem ./install_amazon.sh
```

Then, you can run the experiments with:

```console
OP_IP=54.209.156.87 RP_IP=54.87.166.113 AMAZON_PEM_FILE=~/teste.pem REPEAT=50 ./run_experiments.sh
```

**Warning**: `tcpdump`s grow quickly. E.g. if you run `REPEAT=50 ./run_experiments.sh` you will get around 5GB of pcap files.

## Tips

1. If, for some reason, you need to recreate the TLS certificates, then you need to remove the existing containers and, most importantly, the volumes:

```console
docker kill $(docker ps -q)
docker rm $(docker ps -q -a)
docker volume rm post_quantum_op_certs post_quantum_rp_certs
docker rmi -f $(docker images -a --filter=dangling=true -q)
```

2. If, for some reason, you need to remove **EVERYTHING** and start from scratch:

```console
docker system prune -a --volumes -f
```

3. If you want to evaluate the TLS handshake times like we did in our paper, you can use [our tool built for this purpose](https://sol.sbc.org.br/index.php/sbseg_estendido/article/view/21693/21517).

## Usage Examples:

Run with no TLS; JWT using RSA; and 100 tests locally:

```console
TLS_SIGN= JWT_SIGN=rsa REPEAT=100 docker-compose up --exit-code-from user_agent op rp user_agent
user_agent_1          | Storing detailed logs (times + sizes) on /app/logs/detailed/TEST=all RP=rp OP=op TLS= JWT=rsa REPEAT=100.csv
user_agent_1          | Storing resumed logs (times + sizes) on /app/logs/resumed_TEST=all.csv
user_agent_1          | Min time:	 0.063583
user_agent_1          | Max time:	 0.103506
user_agent_1          | Mean time:	 0.066275
user_agent_1          | Stdev time:	 0.004112
user_agent_1          | 
user_agent_1          | Mean req/sec:	 317.705191
user_agent_1          | Stdev req/sec:	 13.964885
user_agent_1          | 
user_agent_1          | Mean resp size:	 1006559.000000
user_agent_1          | Stdev resp size: 0.000000
```

Run with TLS using Dilithium 5, JWT using Falcon-512 and 100 tests:
```console
TLS_SIGN=dilithium5 JWT_SIGN=falcon512 REPEAT=100 docker-compose up --exit-code-from user_agent op rp user_agent
user_agent_1          | Storing detailed logs (times + sizes) on /app/logs/detailed/TEST=all RP=rp OP=op TLS=dilithium5 JWT=falcon512 REPEAT=100.csv
user_agent_1          | Storing resumed logs (times + sizes) on /app/logs/resumed_TEST=all.csv
user_agent_1          | Min time:	 0.088119
user_agent_1          | Max time:	 0.130666
user_agent_1          | Mean time:	 0.092610
user_agent_1          | Stdev time:	 0.004317
user_agent_1          | 
user_agent_1          | Mean req/sec:	 227.131523
user_agent_1          | Stdev req/sec:	 8.208270
user_agent_1          | 
user_agent_1          | Mean resp size:	 1009611.260000
user_agent_1          | Stdev resp size: 5.125929
```

To see what is rolling behind the scenes try this:
```console
TLS_SIGN=ecdsa JWT_SIGN=rsa LOG_LEVEL=DEBUG docker-compose up --exit-code-from user_agent op rp user_agent
```
