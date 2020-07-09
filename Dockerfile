FROM golang:1.14 as builder
RUN mkdir /build
ADD . /build
WORKDIR /build
RUN CGO_ENABLED=0 go build -o wgrpcd cmd/wgrpcd/wgrpcd.go
FROM alpine
RUN mkdir /wgrpcd
COPY --from=builder /build/wgrpcd /wgrpcd/wgrpcd
WORKDIR /wgrpcd
ENTRYPOINT [ "./wgrpcd" ]
EXPOSE 15002