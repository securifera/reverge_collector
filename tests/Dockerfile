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
RUN /tmp/install.sh

CMD ["/bin/bash", "-c", "source ~/venv/bin/activate && pytest tests/"]
