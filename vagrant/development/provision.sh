#! /usr/bin/env bash

# Install development dependencies
sudo apt-get update -qq
sudo apt-get install -qq software-properties-common
sudo add-apt-repository -y ppa:yubico/stable
sudo apt-get update -qq && apt-get -qq upgrade
sudo apt-get install -qq \
    virtualbox-guest-dkms \
    cmake \
    libqt4-dev \
    qt4-default \
    qt4-qmake \
    python-dev \
    python-pip \
    python-pyside=1.2.2-2build2 \
    python-setuptools \
    pyside-tools \
    libykpiv1 \
    xfce4 \
    yubico-piv-tool
pip install --upgrade pip

# Install flake8 for linting
pip install pre-commit flake8

# Fix permissions in repo, install pre-commit hook
cd /vagrant && chown -R ubuntu . && pre-commit install

# Set a root password to enable login from GUI
# Do startx after login to launch xfce4
sudo echo "root:root" | sudo chpasswd

# Make ubuntu user passwordless
sudo passwd -d ubuntu

# Add manifest file missing from PySide package

cat << EOF | sudo tee /usr/lib/python2.7/dist-packages/PySide-1.2.2-2build2.egg-info
Metadata-Version: 1.0
Name: PySide
Version: 1.2.2-2build2
Summary: UNKNOWN
Home-page: http://www.pyside.org/
Author: UNKNOWN
Author-email: UNKNOWN
License: UNKNOWN
Description: Python bindings for Qt4
Platform: UNKNOWN
Summary: UNKNOWN
EOF
