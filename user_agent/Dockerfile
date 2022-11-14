# Multi-stage build: First the full builder image:
FROM alpine:3.11 as liboqs-python-wrapper

# Take in all global args
ARG LIBOQS_BUILD_DEFINES="-DOQS_DIST_BUILD=ON -DBUILD_SHARED_LIBS=ON -DOQS_USE_OPENSSL=OFF"
ARG MAKE_DEFINES="-j 2"

LABEL version="2"

ENV DEBIAN_FRONTEND noninteractive

RUN apk update && apk upgrade

# Get all software packages required for builing all components:
RUN apk add build-base linux-headers cmake ninja git

# get all sources
WORKDIR /opt
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs && \
    git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs-python.git 

# build liboqs 
WORKDIR /opt/liboqs

# FIXME: had to go back a few commits for to get the generate.py script working, that's why we have two generate.yml files
RUN git fetch --depth=1 origin af76ca3b1f2fbc1f4f0967595f3bb07692fb3d82
RUN git checkout af76ca3b1f2fbc1f4f0967595f3bb07692fb3d82
RUN git branch -D @{-1}

RUN mkdir build && cd build && cmake -GNinja .. ${LIBOQS_BUILD_DEFINES} && ninja install

WORKDIR /opt
RUN git clone --depth 1 --branch OQS-OpenSSL_1_1_1-stable https://github.com/open-quantum-safe/openssl.git 

WORKDIR /opt/openssl

RUN apk add py3-pip
RUN pip3 install --no-cache --upgrade pip setuptools
RUN pip3 install Jinja2 PyYAML tabulate

# FIXME: had to go back a few commits for to get the generate.py script working
RUN git fetch --depth=1 origin ea1ab6797ec829e8440639995b061c3b81234b14
RUN git checkout ea1ab6797ec829e8440639995b061c3b81234b14
RUN git branch -D @{-1}

ARG LIBOQS_DOCS_DIR=/opt/liboqs/docs
ARG LIBOQS_SRC_DIR=/opt/liboqs
COPY generate_openssl_1.1.1.yml oqs-template/generate.yml
RUN python3 oqs-template/generate.py

WORKDIR /opt/liboqs

RUN mkdir build-openssl && cd build-openssl && cmake -G"Ninja" .. ${LIBOQS_BUILD_DEFINES} -DCMAKE_INSTALL_PREFIX=/opt/openssl/oqs && ninja install

RUN apk add automake autoconf && cd /opt/openssl && LDFLAGS="-Wl,-rpath -Wl,/usr/local/lib64" ./Configure shared linux-x86_64 -lm && make generate_crypto_objects && make ${MAKE_DEFINES} && make install_sw

WORKDIR /opt/liboqs-python

# FIXME: had to go back a few commits for to get the generate.py script working
RUN git fetch --depth=1 origin ff976e68e225980d7003db6aa8b82dbaf9279fa5
RUN git checkout ff976e68e225980d7003db6aa8b82dbaf9279fa5
RUN git branch -D @{-1}

## second stage: Only create minimal image without build tooling and liboqs-python-wrapper build results generated above:
FROM python:3.10-alpine3.13

# Get all software packages required for running all components:
RUN apk update && apk upgrade && apk add python3-dev gcc libc-dev libffi-dev openldap-dev

# Only retain the binary contents in the final image
COPY --from=liboqs-python-wrapper /usr/local /usr/local
COPY --from=liboqs-python-wrapper /opt/liboqs-python /opt/liboqs-python

ENV PYTHONPATH=/opt/liboqs-python

COPY app/requirements.txt .

USER root

ENV LD_LIBRARY_PATH=
RUN pip3 install --no-cache --upgrade pip setuptools
RUN pip3 install -r requirements.txt
ENV LD_LIBRARY_PATH='/usr/local/lib64'

COPY app /app
WORKDIR /app

CMD ["python3", "app.py"]
