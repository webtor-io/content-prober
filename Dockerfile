# golang image
FROM golang:latest AS build

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

FROM jrottenberg/ffmpeg:8-alpine

# set work dir
WORKDIR /app

# copy our static linked library
COPY --from=build /app/server/server .

# tell we are exposing our service ports
EXPOSE 50051 8080 8081

ENTRYPOINT []

# run it!
CMD ["./server"]
