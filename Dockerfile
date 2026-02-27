# ffmpeg image
FROM jrottenberg/ffmpeg:snapshot-alpine AS ffmpeg

# golang image
FROM golang:1.26 AS build

# set work dir
WORKDIR /app

# copy go module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# copy the source files
COPY . .

# disable crosscompiling
ENV CGO_ENABLED=0

# compile linux only
ENV GOOS=linux

# build the binary with debug information removed
RUN cd ./server && go build -ldflags '-w -s' -a -installsuffix cgo -o server

FROM alpine:latest

# copy static ffmpeg to use later 
COPY --from=ffmpeg /usr/local /usr/local

# install additional dependencies for ffmpeg
RUN apk add --no-cache --update libgcc libstdc++ ca-certificates libcrypto3 libssl3 libgomp expat

# copy our static linked library
COPY --from=build /app/server/server .

# tell we are exposing our service ports
EXPOSE 50051
EXPOSE 8080
EXPOSE 8081

# run it!
CMD ["./server"]