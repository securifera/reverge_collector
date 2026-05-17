#!/bin/sh
arch="linux_amd64"
install_packages() {
    # Wait for the dpkg lock to be released.
    while ps -opid= -C apt-get > /dev/null; do sleep 10; done;
    sudo apt-get update
    while ps -opid= -C apt-get > /dev/null; do sleep 10; done;
    sudo DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" install -y $*
}

# Verify that a freshly installed tool actually landed somewhere usable.
# Without this, a silent install failure (bad build, wrong release asset,
# directory-vs-file mv collision, etc.) shows up much later as a confusing
# pytest error like "sudo: /usr/local/bin/X: command not found". Call right
# after every binary install step.
verify_binary() {
    name="$1"
    path="$2"
    if [ ! -x "$path" ] || [ -d "$path" ]; then
        echo "INSTALL ERROR: $name not installed correctly at $path" >&2
        ls -la "$path" >&2 2>/dev/null || echo "  (path does not exist)" >&2
        exit 1
    fi
    echo "  verified: $name at $path"
}

# Fetch a GitHub release JSON and validate it actually contains assets.
# Uses GITHUB_TOKEN if set (raises rate limit from 60 → 5000 req/hr) — CI
# Docker builds were silently rate-limited by GitHub, which returns a JSON
# error object with no .assets field, making `jq '.assets[]'` blow up with
# "Cannot iterate over null". The result is printed to stdout so callers
# can pipe it to jq. On failure we dump the HTTP code and the response body
# itself, since the API has many failure modes (rate limit, auth error,
# upstream HTML error page, empty body) and a generic "no assets" message
# doesn't tell you which.
gh_release_json() {
    repo="$1"        # e.g. securifera/nmap or projectdiscovery/naabu
    tag="${2:-latest}"  # 'latest' or a specific tag like 'v2.6.1'
    if [ "$tag" = "latest" ]; then
        api_url="https://api.github.com/repos/${repo}/releases/latest"
    else
        api_url="https://api.github.com/repos/${repo}/releases/tags/${tag}"
    fi
    body_file=$(mktemp)
    err_file=$(mktemp)
    if [ -n "$GITHUB_TOKEN" ]; then
        http_code=$(curl -k -sS \
            -H "Authorization: Bearer $GITHUB_TOKEN" \
            -H "Accept: application/vnd.github+json" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            -w '%{http_code}' -o "$body_file" "$api_url" 2>"$err_file")
    else
        http_code=$(curl -k -sS \
            -H "Accept: application/vnd.github+json" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            -w '%{http_code}' -o "$body_file" "$api_url" 2>"$err_file")
    fi
    # Read body straight from file so we don't round-trip a large JSON
    # response through a shell variable (where embedded escapes or NULs
    # can silently mangle the payload before jq sees it).
    if ! jq -e '.assets | length > 0' "$body_file" >/dev/null 2>&1; then
        echo "ERROR: GitHub API for $repo ($tag) returned no usable release assets." >&2
        echo "  endpoint:  $api_url" >&2
        echo "  http_code: $http_code" >&2
        echo "  token:     $([ -n "$GITHUB_TOKEN" ] && echo "present (${#GITHUB_TOKEN} chars)" || echo "absent")" >&2
        echo "  body_size: $(wc -c < "$body_file") bytes" >&2
        echo "  asset_count (jq):  $(jq -r '.assets | length' "$body_file" 2>&1 | head -c 200)" >&2
        echo "  asset_names (jq):  $(jq -r '[.assets[]?.name] | @csv' "$body_file" 2>&1 | head -c 400)" >&2
        if [ -s "$err_file" ]; then
            echo "  curl stderr:" >&2
            sed 's/^/    /' "$err_file" >&2
        fi
        echo "  body first 400 chars:" >&2
        head -c 400 "$body_file" | sed 's/^/    /' >&2
        echo "" >&2
        echo "  body last 400 chars:" >&2
        tail -c 400 "$body_file" | sed 's/^/    /' >&2
        echo "" >&2
        if [ -z "$GITHUB_TOKEN" ]; then
            echo "  hint: pass GITHUB_TOKEN as a docker build-arg to avoid the 60 req/hr unauthenticated rate limit." >&2
        fi
        rm -f "$body_file" "$err_file"
        exit 1
    fi
    cat "$body_file"
    rm -f "$body_file" "$err_file"
}


while getopts ":a:" opt; do
  case $opt in
    a) arch="$OPTARG"
    ;;
    \?) echo "Invalid option -$OPTARG" >&2
    exit 1
    ;;
  esac

  case $OPTARG in
    -*) echo "Option $opt needs a valid argument"
    exit 1
    ;;
  esac
done

cd "$( dirname "${BASH_SOURCE[0]}" )"

# Check if python3 command is available
if command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
    PYTHON3="yes"
elif command -v python &>/dev/null; then
    # Check if the 'python' command points to Python 3.x
    if [ `python -c "import sys; print(sys.version_info.major)"` = "3" ]; then
        echo "Python 3.x found."
        PYTHON_CMD="python"
        PYTHON3="yes"
    else
        echo "Python 3.x not found. Installing Python 3.13..."
        NEED_INSTALL="yes"
    fi
else
    echo "Python 3.x not found. Installing Python 3.13..."
    NEED_INSTALL="yes"
fi

if [ "$PYTHON3" = "yes" ]; then
    PYTHON_VERSION=$($PYTHON_CMD -c "import sys; print(sys.version_info.minor)")
    echo "Current Python version: 3.$PYTHON_VERSION"

    if [ `echo "$PYTHON_VERSION 12" | awk '{print ($1 < $2)}'` -eq 1 ]; then
        echo "Python version is less than 3.13. Installing Python 3.13..."
        NEED_INSTALL="yes"
    fi
fi

if [ "$NEED_INSTALL" = "yes" ]; then
    # Update package list and install prerequisites
    install_packages software-properties-common

    # Add the deadsnakes PPA
    sudo add-apt-repository -y ppa:deadsnakes/ppa

    # Install Python 3.13
    install_packages python3.13 python3.13.dev python3.13-venv

    curl -sS https://bootstrap.pypa.io/get-pip.py | sudo python3.13

    python3.13 -m venv ~/venv
    . ~/venv/bin/activate

    echo "Python 3.13 installed successfully."
else
    install_packages python3-venv
    python3 -m venv ~/venv
    . ~/venv/bin/activate
fi 

# install initial tools
install_packages ca-certificates wget curl net-tools git screen jq unzip supervisor gnupg apt-transport-https

openssl s_client -showcerts -connect google.com:443 < /dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > ca.crt
sudo cp ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# install python pip'
install_packages python3-pip pipx
pip3 config set global.trusted-host "pypi.org files.pythonhosted.org pypi.python.org" --trusted-host=pypi.python.org --trusted-host=pypi.org --trusted-host=files.pythonhosted.org

# install reverge_collector dependencies
python3 -m pip install setuptools build poetry
python3 -m pip install --upgrade requests

# Build and install reverge_collector
poetry build
python3 -m pip install dist/reverge_collector*.whl
sudo mkdir -p /opt/collector
sudo cp ./reverge_collector/scan_poller.py /opt/collector/

###############
# scanner stuff
###############

# dependencies
install_packages libssl-dev libpcap-dev masscan autoconf build-essential

# install nmap
cd /tmp; gh_release_json securifera/nmap | jq -r ".assets[] | select(.name | contains(\"$arch\")) | .browser_download_url" | sudo wget --no-check-certificate -i - ; sudo tar --preserve-permissions -xzf nmap*.tar.gz -C / ; sudo rm nmap*.tar.gz
verify_binary nmap /usr/local/bin/nmap

# Install Go (required to build naabu / nuclei / httpx from source).
if ! command -v go &>/dev/null; then
    GO_VERSION=$(curl -s https://go.dev/VERSION?m=text | head -1)
    cd /tmp; wget -q "https://go.dev/dl/${GO_VERSION}.linux-amd64.tar.gz"; sudo tar -C /usr/local -xzf "${GO_VERSION}.linux-amd64.tar.gz"; rm "${GO_VERSION}.linux-amd64.tar.gz"
    export PATH=$PATH:/usr/local/go/bin
fi

# Install naabu — built from the securifera fork's source.
# Background: projectdiscovery's published release binaries (every tag we
# tested, v2.3.x through v2.6.1) fatal-exit with "service discovery feature
# is not implemented" when -sD/-sV is used. The OSS *source* actually has
# working native fingerprinting (added by PR #1667, merged Mar 2026) — but
# their release pipeline apparently rebuilds against a private branch that
# re-applies the stub. The only reliable way to get a working binary is to
# build it ourselves from source. We pull from the securifera fork so we
# control the artifact surface.
cd /tmp
sudo rm -rf /tmp/naabu-src /tmp/naabu-bin
git clone -c http.sslVerify=false --depth 1 https://github.com/securifera/naabu.git /tmp/naabu-src
cd /tmp/naabu-src
go build -buildvcs=false -o /tmp/naabu-bin ./cmd/naabu
sudo install -m 0755 /tmp/naabu-bin /usr/local/bin/naabu
cd /tmp; sudo rm -rf /tmp/naabu-src /tmp/naabu-bin
verify_binary naabu /usr/local/bin/naabu

# Install nuclei (built from securifera fork). Clone into a distinct source
# directory so `go build -o /tmp/nuclei-bin` doesn't collide with the clone
# path — previously `go build -o /tmp/nuclei` wrote the binary INSIDE the
# clone dir, and the subsequent `mv` relocated the whole directory tree.
cd /tmp
sudo rm -rf /tmp/nuclei-src /tmp/nuclei-bin
git clone -c http.sslVerify=false https://github.com/securifera/nuclei.git /tmp/nuclei-src
cd /tmp/nuclei-src
go build -buildvcs=false -o /tmp/nuclei-bin ./cmd/nuclei
sudo install -m 0755 /tmp/nuclei-bin /usr/local/bin/nuclei
cd /tmp; sudo rm -rf /tmp/nuclei-src /tmp/nuclei-bin
verify_binary nuclei /usr/local/bin/nuclei

# Clone our nuclei-templates fork so the scanner only uses our curated templates
sudo git clone -c http.sslVerify=false https://github.com/securifera/nuclei-templates.git /root/nuclei-templates

# nuclei expects a CSV `.templates-index` (template_id,/full/path) at the
# root of the templates directory; without it Nuclei.nuclei_modules() in
# the collector returns an empty list. Upstream nuclei creates this file
# only as a side effect of `-update-templates`, which would replace our
# securifera fork with ProjectDiscovery's official templates. So we
# generate it ourselves from the cloned files: walk every *.yaml and
# extract the first `id:` field. Each template's id is a single line near
# the top of the file (always before the first blank line / `info:`).
sudo find /root/nuclei-templates -name "*.yaml" -type f -print0 \
    | sudo xargs -0 -P "$(nproc)" -I {} sh -c '
        id=$(awk "/^id:[[:space:]]+/ {sub(/^id:[[:space:]]+/, \"\"); print; exit}" "$1")
        [ -n "$id" ] && printf "%s,%s\n" "$id" "$1"
    ' _ {} \
    | sudo tee /root/nuclei-templates/.templates-index > /dev/null
sudo chmod 600 /root/nuclei-templates/.templates-index
echo "  generated .templates-index: $(sudo wc -l < /root/nuclei-templates/.templates-index) entries"

# Install gau
cd /tmp; gh_release_json lc/gau | jq -r ".assets[] | select(.name | contains(\"$arch\")) | .browser_download_url" | sudo wget --no-check-certificate -i - ; sudo tar --preserve-permissions -xzf gau*.tar.gz ; sudo mv gau /usr/local/bin/ ; sudo rm gau*.tar.gz
sudo chmod +x /usr/local/bin/gau
verify_binary gau /usr/local/bin/gau

# Screenshot dependencies
install_packages fonts-liberation libgbm1 libappindicator3-1 openssl libasound2t64

# Pyshot & PhantomJs
cd /tmp
git clone -c http.sslVerify=false https://github.com/securifera/pyshot.git
cd pyshot 
tar -C /tmp -xvf phantomjs-2.1.1-linux-x86_64.tar.gz
sudo mv /tmp/phantomjs /usr/bin
python3 -m build
python3 -m pip install dist/pyshot*.whl

# Install HTTPX (built from securifera fork). Same go-build/mv collision as
# nuclei above: keep clone path and binary output path distinct.
cd /tmp
sudo rm -rf /tmp/httpx-src /tmp/httpx-bin
git clone -c http.sslVerify=false https://github.com/securifera/httpx.git /tmp/httpx-src
cd /tmp/httpx-src
go build -o /tmp/httpx-bin ./cmd/httpx
sudo install -m 0755 /tmp/httpx-bin /usr/local/bin/httpx
cd /tmp; sudo rm -rf /tmp/httpx-src /tmp/httpx-bin
verify_binary httpx /usr/local/bin/httpx

# Install Subfinder
cd /tmp; gh_release_json projectdiscovery/subfinder | jq -r ".assets[] | select(.name | contains(\"$arch\")) | .browser_download_url" | sudo wget --no-check-certificate -i - ; sudo unzip -o subfinder*.zip; sudo mv subfinder /usr/local/bin/; sudo rm subfinder*.zip
sudo chmod +x /usr/local/bin/subfinder
verify_binary subfinder /usr/local/bin/subfinder

if [ "$arch" = "linux_arm64" ]
then
    ferox_version="aarch64"
else
    ferox_version="x86_64-linux"
fi

# Install FeroxBuster
cd /tmp; gh_release_json epi052/feroxbuster | jq -r ".assets[] | select(.name | contains(\"$ferox_version-feroxbuster.zip\")) | .browser_download_url" | sudo wget --no-check-certificate -i - ; sudo unzip -o *feroxbuster*.zip; sudo mv feroxbuster /usr/local/bin/ ; sudo rm *feroxbuster*.zip
sudo chmod +x /usr/local/bin/feroxbuster
verify_binary feroxbuster /usr/local/bin/feroxbuster

# Badsecrets
#python3 -m pip install badsecrets
cd /tmp
sudo git clone -c http.sslVerify=false https://github.com/securifera/crapsecrets
cd crapsecrets
poetry build
python3 -m pip install dist/crapsecrets*.whl

# Install Google Chrome
cd /tmp
wget -O /tmp/google-chrome-stable_current_amd64.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
install_packages /tmp/google-chrome-stable_current_amd64.deb
rm -f /tmp/google-chrome-stable_current_amd64.deb

# IIS Shortname Scanner
cd /tmp
git clone -c http.sslVerify=false https://github.com/securifera/IIS_shortname_Scanner.git
cd IIS_shortname_Scanner
python3 -m build
python3 -m pip install dist/iis_shortname_scanner*.whl

# Install Webcap
cd /tmp
git clone -c http.sslVerify=false https://github.com/securifera/webcap.git
cd webcap 
python3 -m build
python3 -m pip install dist/webcap*.whl

# Install netexec
pipx ensurepath
pipx install git+https://github.com/securifera/NetExec
~/.local/bin/netexec --version

# Install metasploit.  The msfinstall script just bootstraps an apt repo and
# installs the rapid7 omnibus .deb, which gives us bundled Ruby, gems, postgres,
# and the bin/ wrappers under /opt/metasploit-framework.  We keep all of that
# but swap the framework code itself for our securifera fork below.
cd /tmp
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && sudo ./msfinstall

# Pin the apt package so `apt upgrade` won't reinstall rapid7's framework over
# our fork.  Run msfupdate manually if you want to refresh the omnibus deps.
sudo apt-mark hold metasploit-framework

# Replace the bundled framework with our fork and reinstall gems using the
# omnibus Ruby/Bundler so any new/changed dependencies in the fork are picked up.
MSF_FW_DIR=/opt/metasploit-framework/embedded/framework
sudo rm -rf "$MSF_FW_DIR"
sudo git clone -c http.sslVerify=false --depth 1 https://github.com/securifera/metasploit-framework.git "$MSF_FW_DIR"

# Ruby 3.4.x ships stringio 3.1.2 as a default gem but the upstream gemspec pins
# to '3.1.1', which causes a gem-activation conflict at runtime.  Relax it here.
sudo sed -i "s/add_runtime_dependency 'stringio', '3\.1\.1'/add_runtime_dependency 'stringio', '>= 3.1.2'/" "$MSF_FW_DIR/metasploit-framework.gemspec"

# Mark the framework dir as safe so git doesn't reject it due to sudo ownership.
sudo git config --global --add safe.directory "$MSF_FW_DIR"

# The omnibus Ruby 3.4 ships psych 5.3.1 as a default gem. The fork's
# Gemfile.lock pins psych 5.2.6, and Ruby activates the default gem first —
# so when bundler tries to require the locked 5.2.6 it crashes with
# "already activated psych 5.3.1, but your Gemfile requires psych 5.2.6"
# and msfdb init fails. We can't delete Gemfile.lock to dodge this: doing
# so unpins Rails, and the fork's config/application.rb explicitly raises
# unless ActionView is exactly 7.2.2.2 (a version-pinned monkey-patch).
# Instead, surgically relax just the psych pin. --conservative tells
# bundler to update only the named gem (and its direct deps), preserving
# every other pin including Rails.
# Bundle must be called with the omnibus bin/ in PATH so that the 'bundle'
# shebang (#!/usr/bin/env ruby) resolves to the omnibus Ruby 3.4, not the
# system Ruby which may be an older version.
cd "$MSF_FW_DIR"
sudo env PATH=/opt/metasploit-framework/embedded/bin:$PATH bundle update --conservative psych
sudo env PATH=/opt/metasploit-framework/embedded/bin:$PATH bundle install --jobs 4
cd -

# Create a dedicated non-root user for msfdb and the JSON RPC server.
# msfdb explicitly refuses to run as root; all msf state lives under this user's home.
sudo useradd -r -m -s /bin/bash msf 2>/dev/null || true

# msfdb runs as the msf user and loads the framework via git; add the safe
# directory for that user too so git doesn't reject the root-owned clone.
sudo -u msf git config --global --add safe.directory /opt/metasploit-framework/embedded/framework

# Initialize the embedded PostgreSQL database as the msf user.
# msfdb manages its own postgres instance (port 5433) under ~/.msf4/db — no system
# postgres required.  --component database skips the interactive webservice wizard;
# --use-defaults accepts all prompts non-interactively.
sudo -u msf /opt/metasploit-framework/bin/msfdb init --component database --use-defaults

# Generate a random 40-hex-char bearer token for the JSON RPC API and persist it.
# The collector reads this via MSF_JSON_RPC_TOKEN env var; puma uses MSF_WS_JSON_RPC_API_TOKEN.
MSF_TOKEN=$(openssl rand -hex 20)
echo "$MSF_TOKEN" | sudo tee /opt/collector/msf_rpc_token > /dev/null
sudo chmod 644 /opt/collector/msf_rpc_token

# Install sqlmap
sudo git clone -c http.sslVerify=false https://github.com/securifera/sqlmap.git /opt/sqlmap
sudo chmod +x /opt/sqlmap/sqlmap.py

# Clean seclists in the background
sudo git clone -c http.sslVerify=false https://github.com/danielmiessler/SecLists.git /usr/share/seclists &
