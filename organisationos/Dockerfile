FROM ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git build-essential gcc-mingw-w64-x86-64-posix zip python3 && rm -rf /var/lib/apt/lists/*
RUN curl --fail --location https://go.dev/dl/go1.27.3.linux-amd64.tar.gz -o /tmp/go.tar.gz && echo '65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40  /tmp/go.tar.gz' | sha256sum --check && tar -C /usr/local -xzf /tmp/go.tar.gz && rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}" GOTOOLCHAIN=local GOMAXPROCS=2 CGO_ENABLED=1 GOFLAGS="-p=2"
WORKDIR /work
