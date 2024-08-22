#!/bin/sh

# install dependancies
sudo apt update && sudo apt upgrade -y
sudo apt install -y wget git default-jdk binutils gdb tmux unzip net-tools

# install pwntools
sudo apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools

# install pwndbg
cd /opt
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
echo source /opt/pwndbg/gdbinit.py >  ~/.gdbinit

echo "[+] FLAG{iN5t4ll_5ucCe55_5t4rt_C7F}"