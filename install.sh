#!/bin/bash
#
# Apoxy installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/apoxy-dev/apoxy-cli/master/scripts/install.sh | bash

# When releasing Apoxy, the releaser should update this version number
# AFTER they upload new binaries.
VERSION="0.1.1"

set -e

function copy_binary() {
  if [[ ":$PATH:" == *":$HOME/bin:"* ]]; then
      if [ ! -d "$HOME/bin" ]; then
        mkdir -p "$HOME/bin"
      fi
      mv apoxy "$HOME/bin/apoxy"
  else
      echo "Installing Apoxy to /usr/local/bin which is write protected"
      echo "If you'd prefer to install Apoxy without sudo permissions, add \$HOME/bin to your \$PATH and rerun the installer"
      sudo mv apoxy /usr/local/bin/apoxy
  fi
}

function install_apoxy() {
  if [[ "$OSTYPE" == "linux"* ]]; then
			# On Linux, "uname -m" reports "aarch64" on ARM 64 bits machines,
			# and armv7l on ARM 32 bits machines like the Raspberry Pi.
			# This is a small workaround so that the install script works on ARM.
			case $(uname -m) in
					aarch64) ARCH=arm64;;
					armv7l)  ARCH=arm;;
					*)       ARCH=$(uname -m);;
			esac
			set -x
			curl -fsSL https://github.com/apoxy-dev/apoxy-cli/releases/download/v$VERSION/apoxy_Linux_$ARCH.tar.gz | tar -xzv apoxy
			copy_binary
  elif [[ "$OSTYPE" == "darwin"* ]]; then
			# On macOS, "uname -m" reports "arm64" on ARM 64 bits machines
			ARCH=$(uname -m)
			set -x
			curl -fsSL https://github.com/apoxy-dev/apoxy-cli/releases/download/v$VERSION/apoxy_Darwin_$ARCH.tar.gz | tar -xzv apoxy
			copy_binary
  else
      set +x
      echo "The Tilt installer does not work for your platform: $OSTYPE"
      echo ""
      echo "If you think your platform should be supported, please file an issue:"
      echo "https://github.com/apoxy-dev/apoxy-cli/issues/new"
      echo "Thank you!"
      exit 1
  fi

  set +x
}

# so that we can skip installation in CI and just test the version check
if [[ -z $NO_INSTALL ]]; then
  install_apoxy
fi

echo "Apoxy installed!"
