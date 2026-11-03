# Container image for the agent's DaemonSet (deploy/kubernetes, deploy/helm). Build it
# from the repository root after `make dist` (the binary comes from dist/, so the image
# holds the same reproducible build as the .deb):
#   docker buildx build --platform linux/amd64,linux/arm64 -f deploy/Dockerfile -t <registry>/portwarden-agent:<version> .
# nft and iptables-save are needed at run time: the agent reads the host firewall with them.
FROM ubuntu:24.04
RUN apt-get update \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nftables iptables ca-certificates \
	&& rm -rf /var/lib/apt/lists/*
ARG TARGETARCH
COPY dist/bin/linux_${TARGETARCH}/portwarden-agent /usr/bin/portwarden-agent
ENTRYPOINT ["/usr/bin/portwarden-agent"]
