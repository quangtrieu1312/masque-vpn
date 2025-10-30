pushd . >/dev/null 2>&1
scriptDir=$(dirname $(realpath '$0'))
mkdir -p $scriptDir/build
rm -rf $scriptDir/build/*
cd $scriptDir/src
go build -o $scriptDir/build/server
popd >/dev/null 2>&1
