scriptFolder=$(dirname $(realpath $0))
pushd . >/dev/null 2>&1
trap 'popd >/dev/null 2>&1' EXIT SIGINT SIGHUP
cd $scriptFolder
mkdir -p $scriptFolder/build
rm -rf $scriptFolder/build/*
cd src
go build -o $scriptFolder/build/masque
if [[ $? -ne 0 ]]; then
    echo "Build failed. Aborting."
    exit 1
fi
echo "Masque binary is available at $scriptFolder/build/masque"
mkdir -p /etc/masque/certs
if [ -f /etc/masque/masque.conf ]; then
    cp $scriptFolder/masque.conf.template /etc/masque/
    echo "Cannot find /etc/masque/masque.conf. Please create one from masque.conf.template."
fi
popd

