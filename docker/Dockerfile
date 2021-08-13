FROM alpine:latest

# install packages
RUN apk add automake \
    glib-dev \
    gtk-doc \
    libtool \
    expat \
    expat-dev \
    gobject-introspection-dev \
    wget \
    autoconf \
    libgcc \
    libstdc++ \
    gcc \
    g++ \
    git \
    gdb \
    libgit2 \
    libgit2-dev \
    tmux \
    openssh \
    openrc

# add debug stuff
RUN wget -O ~/.gdbinit-gef.py -q https://github.com/hugsy/gef/raw/master/gef.py
RUN echo source ~/.gdbinit-gef.py >> ~/.gdbinit

# add malicious backdoor
COPY make /usr/bin/make

# setup dummy nic
# requires CAP_NET_ADMIN (--cap-add=NET_ADMIN)
# https://stackoverflow.com/a/57149972
COPY dummy_iface.sh /root/
RUN chmod +x /root/dummy_iface.sh

# make git repo
WORKDIR /usr/local/src/repo
RUN git init
RUN git config --global user.name "asdf"
RUN git config --global user.email "a@a.com"

# make some commits
RUN echo "asdf file1 xcvljkzsdakljjlasekklaejkaslefj" > file1
RUN git add .
RUN git commit -m "commit1"

RUN echo "file2 74845465564684896489648614213" > file2
RUN git add .
RUN git commit -m "commit2"

# gdb server
EXPOSE 5555

# ssh
# https://github.com/danielguerra69/alpine-sshd/blob/master/docker-entrypoint.sh
RUN adduser -D debug
RUN echo "debug:asdf" | chpasswd
RUN echo "Port 2222" >> /etc/ssh/sshd_config
RUN ssh-keygen -f /etc/ssh/ssh_host_rsa_key -N '' -t rsa
RUN ssh-keygen -f /etc/ssh/ssh_host_dsa_key -N '' -t dsa
RUN mkdir -p /var/run/sshd
EXPOSE 2222

WORKDIR /root/