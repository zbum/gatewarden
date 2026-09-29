FROM rockylinux:8

RUN dnf install -y rpm-build \
	&& dnf clean all
