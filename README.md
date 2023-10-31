# buildkit-alpine
Buildkit Alpine frontend. Only demo purposes for now

## Sample Definition 

```
#syntax=christiandupuis299/bka:v13

contents:
  repositories:
    - https://dl-cdn.alpinelinux.org/alpine/edge/main
  packages:
    - ca-certificates
  binaries:
    - url: https://github.com/argoproj/argo-cd/releases/download/v2.8.4/argocd-linux-arm64
      path: /bin/argocd
      checksum: sha256:683c555ba1901fe67889357fa885d1141a72025ba8a2d0f8e86a2ae5f68d8d2d

# optional environment configuration
environment:
  PATH: /usr/sbin:/sbin:/usr/bin:/bin

cmd: /bin/argocd version
```
