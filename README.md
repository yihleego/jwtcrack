# JWTCrack

[![GoDoc](https://godoc.org/github.com/yihleego/jwtcrack?status.svg)](https://godoc.org/github.com/yihleego/jwtcrack)
[![Go Report Card](https://goreportcard.com/badge/github.com/yihleego/jwtcrack)](https://goreportcard.com/report/github.com/yihleego/jwtcrack)

A JWT brute-force cracker written in Go. If you are very lucky or have a huge computing power, this program should find the secret key of a JWT token, allowing you to forge valid tokens.

## Build

```shell
go build
```

## Run

```shell
./jwtcrack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiand0Y3JhY2sifQ.2R40frvzOUV4gO3fgLamhB1tRVUD3IX8FqTiWqp0Iho abcedrst
```

## Build a Docker Image

```shell
docker build . -t jwtcrack
```

## Run on Docker

```shell
docker run -it --rm jwtcrack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiand0Y3JhY2sifQ.2R40frvzOUV4gO3fgLamhB1tRVUD3IX8FqTiWqp0Iho abcedrst
```

## Usage

```shell
./jwtcrack <token> [alphabet] [maxlen] [algorithm]
```

### HS256

```shell
./jwtcrack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiand0Y3JhY2sifQ.QXaZSGwc4eyj3SW_IkIVKsruB1H7WlOr3XMtw_LeODY abcde12345 6 HS256
```

### HS384

```shell
./jwtcrack eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiand0Y3JhY2sifQ.kh07R5GxeApHgXnfm_3CpRo8Ky1ZD66zCb-lk-9-AQb549c50PU1c8BBSxkDewlm abcde12345 6 HS384
```

### HS512

```shell
./jwtcrack eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiand0Y3JhY2sifQ.6J3aomWAWAA-K2goUqsgi9VJJ4O6tuG-xe-_nmWr1UMzj79B9sBQumpPtWYQ4geYx5wckFLnd_9rXpdyFv-sRw abcde12345 6 HS512
```

## License

This project is under the MIT license. See the [LICENSE](LICENSE) file for details.
