FROM --platform=arm64 debian:13

ENV DEBIAN_FRONTEND=noninteractive
ENV DEBCONF_NOWARNINGS yes

RUN apt-get update --fix-missing && apt-get -y upgrade --fix-missing
RUN apt-get install --fix-missing --no-install-recommends --no-install-suggests -y \
build-essential \
libteec2 \
libckteec0t64 \
libssl3t64 \
libssl-dev \
optee-client-dev \
libtss2-dev \
vim

RUN useradd -m build -u 1000
RUN apt-get install -y sudo
RUN echo "build ALL=(ALL) NOPASSWD: ALL" | tee -a /etc/sudoers
RUN echo  "Defaults env_keep += \" http_proxy https_proxy no_proxy\"" | tee -a /etc/sudoers

# Fix error "Please use a locale setting which supports utf-8."
# See https://wiki.yoctoproject.org/wiki/TipsAndTricks/ResolvingLocaleIssues
RUN apt-get install -y locales
RUN sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
        echo 'LANG="en_US.UTF-8"'>/etc/default/locale && \
        dpkg-reconfigure --frontend=noninteractive locales && \
        update-locale LANG=en_US.UTF-8

ENV LC_ALL en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US.UTF-8

USER build
WORKDIR /home/build

CMD /bin/bash
