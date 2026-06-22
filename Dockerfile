FROM rust:1.96-alpine AS builder

RUN apk add --no-cache build-base musl-dev pkgconfig

WORKDIR /src
COPY . .

RUN cargo build --release

FROM alpine:3.20

RUN apk add --no-cache bash ca-certificates docker-cli

WORKDIR /app
COPY --from=builder /src/target/release/matrix-invite-portal /usr/local/bin/matrix-invite-portal

EXPOSE 3000

CMD ["matrix-invite-portal"]
