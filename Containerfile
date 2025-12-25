FROM registry.fedoraproject.org/fedora:latest

RUN dnf -y update && \
    dnf -y install llvm clang lld cmake ninja-build make git xorriso && \
    dnf clean all

ENV CC=clang
ENV CXX=clang++
ENV LD=lld