scriptDir=$(dirname $0)
mkdir -p $scriptDir/build
rm -rf $scriptDir/build/*
go build -o $scriptDir/build/server
