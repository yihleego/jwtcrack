FROM golang:alpine

ENV GO111MODULE=on \
    GOOS=linux \
    GOARCH=amd64 \
    GOPROXY="https://goproxy.cn,direct"

WORKDIR /build

COPY main.go .
COPY go.mod .

RUN go build

ENTRYPOINT ["./jwtcrack"]