# Builds examples/scan-target. Run from security/scan with docker compose;
# the build context is the repository root.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /scan-target ./examples/scan-target

FROM alpine:3.20
COPY --from=build /scan-target /scan-target
EXPOSE 8080
ENTRYPOINT ["/scan-target"]
