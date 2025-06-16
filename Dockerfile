FROM rust:slim-bookworm as builder

WORKDIR /usr/src/yt-cipher

COPY ./src ./src
COPY Cargo.lock .
COPY Cargo.toml .

RUN cargo build --release
