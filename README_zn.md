## download
```
git clone git@github.com:containous/traefik.git
cd traefik
git checkout v2.5.6
```

## build webui
```
cd webui
npm install
npm run build
```

## build traefik
```
go generate

go build -v -ldflags "-s -w \
    -X github.com/traefik/traefik/v2/pkg/version.Version=2.5.6 \
    -X github.com/traefik/traefik/v2/pkg/version.BuildDate=2021-12-28_15:00:00" \
    -a -installsuffix nocgo -o ./traefik.exe ./cmd/traefik
```

## build traefik with shell
```
go generate

VERSION := $(shell git rev-list --tags --max-count=1 | git describe --tags )
DATE := $(shell date "+%Y-%m-%d_%H:%M:%S")

go build -v -ldflags "-s -w \
    -X github.com/traefik/traefik/v2/pkg/version.Version=$VERSION \
    -X github.com/traefik/traefik/v2/pkg/version.BuildDate=$DATE" \
    -a -installsuffix nocgo -o ./traefik.exe ./cmd/traefik
```


```
./traefik --configFile=traefik.toml
```
