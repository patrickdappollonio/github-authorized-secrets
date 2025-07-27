FROM gcr.io/distroless/static-debian12:nonroot

ARG TARGETARCH
COPY github-authorized-secrets-${TARGETARCH} /usr/local/bin/github-authorized-secrets

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/github-authorized-secrets"]
CMD ["server", "--config", "/config/config.toml"]
