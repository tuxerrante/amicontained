# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS builder
LABEL maintainer="Alessandro Affinito"

WORKDIR /src
COPY . .

RUN apk add --no-cache ca-certificates && \
    CGO_ENABLED=0 go build -o /amicontained .

# Final stage
FROM alpine:latest
RUN apk update --no-cache &&\
	apk add --no-cache ca-certificates &&\
	apk upgrade --no-cache
COPY --from=builder /amicontained /usr/bin/amicontained
COPY --from=builder /etc/ssl/certs/ /etc/ssl/certs
COPY --chown=nobody:nobody /syscalls_linux.tbl /syscalls_linux.tbl
USER nobody
ENTRYPOINT ["/usr/bin/amicontained"]
CMD ["--help"]
