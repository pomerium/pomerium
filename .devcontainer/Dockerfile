# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.137.0/containers/go/.devcontainer/base.Dockerfile
FROM mcr.microsoft.com/vscode/devcontainers/go:0-1@sha256:ec4067ba197ea0c44268641bd252c0bdfa61228202cee5f447925f9ac76d59b3

# [Optional] Install a version of Node.js using nvm for front end dev
ARG INSTALL_NODE="true"
ARG NODE_VERSION="lts/*"
RUN if [ "${INSTALL_NODE}" = "true" ]; then su vscode -c "source /usr/local/share/nvm/nvm.sh && nvm install ${NODE_VERSION} 2>&1"; fi

# install envoy
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
	&& apt-get -y install --no-install-recommends \
	apt-transport-https \
	ca-certificates \
	curl \
	gnupg-agent \
	software-properties-common

RUN curl -sL 'https://getenvoy.io/gpg' | sudo apt-key add -

RUN add-apt-repository \
	"deb [arch=amd64] https://dl.bintray.com/tetrate/getenvoy-deb \
	$(lsb_release -cs) \
	stable"

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
	&& apt-get -y install --no-install-recommends getenvoy-envoy


# [Optional] Uncomment the next line to use go get to install anything else you need
# RUN go get -x <your-dependency-or-tool>

# [Optional] Uncomment this line to install global node packages.
# RUN su vscode -c "source /usr/local/share/nvm/nvm.sh && npm install -g <your-package-here>" 2>&1
