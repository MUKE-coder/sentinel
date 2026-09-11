# Builds examples/multi-replica. Run from examples/multi-replica with docker
# compose; the build context is the repository root.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /app ./examples/multi-replica

FROM alpine:3.20
COPY --from=build /app /app
EXPOSE 8080
ENTRYPOINT ["/app"]
