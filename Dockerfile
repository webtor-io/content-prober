# ffmpeg image
FROM jrottenberg/ffmpeg:4.0-alpine AS ffmpeg

# golang image
FROM golang:1.11.5-alpine3.8 AS build

# copy the source files
COPY . /go/src/bitbucket.org/vintikzzzz/content-prober

# set workdir
WORKDIR /go/src/bitbucket.org/vintikzzzz/content-prober/server

# enable modules
ENV GO111MODULE=on

# disable crosscompiling 
ENV CGO_ENABLED=0

# compile linux only
ENV GOOS=linux

# build the binary with debug information removed
RUN go build -mod=vendor -ldflags '-w -s' -a -installsuffix cgo -o server

FROM alpine:3.8

# copy static ffmpeg to use later 
COPY --from=ffmpeg /usr/local /usr/local

# install additional dependencies for ffmpeg
RUN apk add --no-cache --update libgcc libstdc++ ca-certificates libcrypto1.0 libssl1.0 libgomp expat

# copy our static linked library
COPY --from=build /go/src/bitbucket.org/vintikzzzz/content-prober/server/server .

# tell we are exposing our service on port 50051
EXPOSE 50051

# run it!
CMD ["./server"]