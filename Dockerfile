FROM golang:1.20 as build

WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o foxcal .

FROM alpine:latest
COPY --from=build /app/foxcal /foxcal
ENTRYPOINT ["/foxcal"]
EXPOSE 8000
