FROM rust:1.67

WORKDIR /usr/src/myapp
COPY . .

RUN ["cargo", "build", "--release"]

ENTRYPOINT [ "cargo", "run", "--release", "--"]
CMD ["tutor"]
