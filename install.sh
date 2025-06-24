#!/bin/sh
arch="linux_amd64"
install_packages() {
    # Wait for the dpkg lock to be released.
    while ps -opid= -C apt-get > /dev/null; do sleep 10; done;    
    sudo apt-get update
    while ps -opid= -C apt-get > /dev/null; do sleep 10; done;
    sudo DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" install -y $*
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
        echo "Python 3.x not found. Installing Python 3.12..."
        NEED_INSTALL="yes"
    fi
else
    echo "Python 3.x not found. Installing Python 3.12..."
    NEED_INSTALL="yes"
fi

if [ "$PYTHON3" = "yes" ]; then
    PYTHON_VERSION=$($PYTHON_CMD -c "import sys; print(sys.version_info.minor)")
    echo "Current Python version: 3.$PYTHON_VERSION"

    if [ `echo "$PYTHON_VERSION 12" | awk '{print ($1 < $2)}'` -eq 1 ]; then
        echo "Python version is less than 3.12. Installing Python 3.12..."
        NEED_INSTALL="yes"
    fi
fi

if [ "$NEED_INSTALL" = "yes" ]; then
    # Update package list and install prerequisites
    install_packages software-properties-common

    # Add the deadsnakes PPA
    sudo add-apt-repository -y ppa:deadsnakes/ppa

    # Install Python 3.12
    install_packages python3.12 python3.12.dev python3.12-distutils python3.12-venv

    curl -sS https://bootstrap.pypa.io/get-pip.py | python3.12

    python3.12 -m venv ~/venv
    . ~/venv/bin/activate

    echo "Python 3.12 installed successfully."
else
    install_packages python3.12-venv
    python3.12 -m venv ~/venv
    . ~/venv/bin/activate
fi 

# install initial tools
install_packages ca-certificates wget curl net-tools git screen jq unzip supervisor gnupg apt-transport-https

openssl s_client -showcerts -connect google.com:443 < /dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > ca.crt
sudo cp ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# install python pip'
install_packages python3-pip
pip3 config set global.trusted-host "pypi.org files.pythonhosted.org pypi.python.org" --trusted-host=pypi.python.org --trusted-host=pypi.org --trusted-host=files.pythonhosted.org

# install luigi/waluigi
python3 -m pip install luigi setuptools build poetry
python3 -m pip install --upgrade requests

# Create luigi config file
sudo mkdir /opt/collector
echo "[worker]" | sudo tee /opt/collector/luigi.cfg
echo "no_install_shutdown_handler=True" | sudo tee -a /opt/collector/luigi.cfg

sudo mkdir /opt/reverge_collector
cp -r ./waluigi /opt/reverge_collector/
cp ./pyproject.toml /opt/reverge_collector/
sudo chmod -R 777 /opt/reverge_collector
cd /opt/reverge_collector 
python3 -m build
python3 -m pip install dist/waluigi*.whl

###############
# scanner stuff
###############

# dependencies
install_packages libssl-dev libpcap-dev masscan autoconf build-essential

# install nmap
cd /opt
sudo git clone -c http.sslVerify=false https://github.com/securifera/nmap.git
cd nmap && sudo git checkout ssl_updates && sudo ./configure --without-ncat --without-zenmap --without-nping && sudo make && sudo make install

# Install nuclei
cd /tmp; curl -k -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r ".assets[] | select(.name | contains(\"$arch\")) | .browser_download_url" | sudo wget --no-check-certificate -i - ; sudo unzip -o nuclei*.zip; sudo mv nuclei /usr/local/bin/ ; sudo rm nuclei*.zip
sudo chmod +x /usr/local/bin/nuclei

# Screenshot dependencies
install_packages fonts-liberation libgbm1 libappindicator3-1 openssl libasound2

# Pyshot & PhantomJs
cd /tmp
git clone -c http.sslVerify=false https://github.com/securifera/pyshot.git
cd pyshot 
tar -C /tmp -xvf phantomjs-2.1.1-linux-x86_64.tar.gz
sudo mv /tmp/phantomjs /usr/bin
python3 -m build
python3 -m pip install dist/pyshot*.whl

# Install HTTPX
cd /tmp; curl -k -s https://api.github.com/repos/projectdiscovery/httpx/releases/latest | jq -r ".assets[] | select(.name | contains(\"$arch\")) | .browser_download_url" | sudo wget --no-check-certificate -i - ; sudo unzip -o httpx*.zip; sudo mv httpx /usr/local/bin/ ; sudo rm httpx*.zip
sudo chmod +x /usr/local/bin/httpx

# Install Subfinder
cd /tmp; curl -k -s https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | jq -r ".assets[] | select(.name | contains(\"$arch\")) | .browser_download_url" | sudo wget --no-check-certificate -i - ; sudo unzip -o subfinder*.zip; sudo mv subfinder /usr/local/bin/; sudo rm subfinder*.zip
sudo chmod +x /usr/local/bin/subfinder

if [ "$arch" = "linux_arm64" ]
then
    ferox_version="aarch64"
else
    ferox_version="x86_64-linux"
fi

# Install FeroxBuster
cd /tmp; curl -k -s https://api.github.com/repos/epi052/feroxbuster/releases/latest | jq -r ".assets[] | select(.name | contains(\"$ferox_version-feroxbuster.zip\")) | .browser_download_url" | sudo wget --no-check-certificate -i - ; sudo unzip -o *feroxbuster*.zip; sudo mv feroxbuster /usr/local/bin/ ; sudo rm *feroxbuster*.zip
sudo chmod +x /usr/local/bin/feroxbuster
sudo git clone -c http.sslVerify=false https://github.com/danielmiessler/SecLists.git /usr/share/seclists

# Badsecrets
python3 -m pip install badsecrets

# Install Google Chrome
wget -O /tmp/google-chrome-stable_current_amd64.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
apt-get install -y /tmp/google-chrome-stable_current_amd64.deb
rm -f /tmp/google-chrome-stable_current_amd64.deb

# Install Webcap
cd /tmp
git clone -c http.sslVerify=false https://github.com/securifera/webcap.git
cd webcap 
python3 -m build
python3 -m pip install dist/webcap*.whl
