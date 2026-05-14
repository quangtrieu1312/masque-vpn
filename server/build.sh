pushd . >/dev/null 2>&1
scriptDir=$(dirname $(realpath "$0"))
mkdir -p $scriptDir/build
rm -rf $scriptDir/build/*
cd $scriptDir/src
if [ "$(uname -m)" = "x86_64" ]; then
    export CGO_CXXFLAGS="-std=c++17 -mcx16"
else
    export CGO_CXXFLAGS="-std=c++17"
fi
go build -o $scriptDir/build/bin
popd >/dev/null 2>&1
