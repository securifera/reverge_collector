FROM ubuntu:24.04

ENV TZ=America/New_York

# Dockerfile metadata
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezoneLABEL version="1.0"

LABEL desription="Collector Docker Pytest Image"

# Setup initial environment
ENV DEBIAN_FRONTEND noninteractive
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

CMD ["/bin/bash", "-c", "source ~/venv/bin/activate && pytest tests/"]
