FROM ubuntu:24.04

ENV TZ=America/New_York

# Dockerfile metadata
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
LABEL version="1.0"
LABEL desription="Collector Docker Pytest Image"

# Setup initial environment
ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-c"]
WORKDIR /tmp

RUN apt update
RUN apt install sudo -y
COPY . /tmp/
RUN chmod +x /tmp/install.sh
# GITHUB_TOKEN raises the GitHub API rate limit from 60 → 5000 req/hr.
# install.sh hits the API for several tool releases in rapid succession;
# without the token the Docker build IP gets rate-limited and tools fail
# to install with a cryptic "jq: Cannot iterate over null" error.
ARG GITHUB_TOKEN=""
RUN GITHUB_TOKEN="$GITHUB_TOKEN" /tmp/install.sh

# Install dev tooling (ruff for lint/format, pytest-cov for coverage gate,
# pytest-mock for the mocker fixture used by some tests) into the same venv
# that install.sh set up at ~/venv. Keeping these out of pyproject.toml's
# runtime deps avoids forcing operators to install ruff on production
# collectors.
RUN source ~/venv/bin/activate && pip install --no-cache-dir \
        'ruff>=0.6.0' \
        'pytest-cov>=5.0' \
        'pytest-mock>=3.14'

# Need `make` itself (Ubuntu minimal images sometimes omit it).
RUN apt install -y make

# CI runs `make ci` (format-check + lint + test-with-coverage). Override
# UV_RUN to empty so ruff is invoked directly from ~/venv instead of
# trying to bootstrap uv inside the image.
CMD ["/bin/bash", "-c", "source ~/venv/bin/activate && cd /tmp && make UV_RUN= PYTEST=pytest ci"]
