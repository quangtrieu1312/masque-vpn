scriptFolder=$(dirname $(realpath '$0'))
mkdir -p ./build
rm -rf ./build/*
sudo docker build . -f Dockerfile.build -t masque-client-builder
sudo docker run \
    --mount src=$scriptFolder/build,target=/build,type=bind \
    --mount src=$scriptFolder/src,target=/src,type=bind \
    masque-client-builder
