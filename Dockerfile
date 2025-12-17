FROM golang:1.25.5-alpine3.23 AS build
COPY . /src
WORKDIR /src

RUN CGO_ENABLED=0 go install -trimpath

FROM alpine:3.23

COPY --from=build /go/bin/pbotp-responder /
ENTRYPOINT ["/pbotp-responder"]
