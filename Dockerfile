FROM golang:1.27-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/paperlens-api ./cmd/api

FROM alpine:3.22
RUN addgroup -S paperlens && adduser -S -G paperlens paperlens && apk add --no-cache ca-certificates
USER paperlens
COPY --from=build /out/paperlens-api /paperlens-api
EXPOSE 8080
ENTRYPOINT ["/paperlens-api"]
