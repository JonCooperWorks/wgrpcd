FROM golang:1.15 AS build

WORKDIR /go/src/github.com/joncooperworks/wgrpcd
COPY . .

RUN go get -d -v ./...
RUN go install -v ./...

EXPOSE 15002
ENTRYPOINT ["wgrpcd"]