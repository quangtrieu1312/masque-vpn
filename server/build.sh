pushd . >/dev/null 2>&1
# Clear stale quic-go cache
go env GOPATH | xargs -I{} rm -rf {}/pkg/mod/cache/download/github.com/quangtrieu1312/quic-go/@v/v0.59.0*
go env GOPATH | xargs -I{} rm -rf {}/pkg/mod/github.com/quangtrieu1312/quic-go@v0.59.0

# Clear stale connect-ip-go cache
go env GOPATH | xargs -I{} rm -rf {}/pkg/mod/cache/download/github.com/quangtrieu1312/connect-ip-go/@v/v0.1.0*
go env GOPATH | xargs -I{} rm -rf {}/pkg/mod/github.com/quangtrieu1312/connect-ip-go@v0.1.0
scriptDir=$(dirname $(realpath "$0"))
mkdir -p $scriptDir/build
rm -rf $scriptDir/build/*
cd $scriptDir/src
CGO_CXXFLAGS="-std=c++17 -mcx16" go build -o $scriptDir/build/bin
popd >/dev/null 2>&1
