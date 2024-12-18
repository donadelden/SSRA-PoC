FROM rust:1.67

WORKDIR /usr/src/myapp
COPY . .

RUN ./builder_linux.sh
ENV RUST_BACKTRACE=1

ENTRYPOINT [ "cargo", "run", "--release", "--"]
CMD ["tutor"]
#CMD [ "run", "--release", "--" ]
#CMD ["/bin/bash"]
