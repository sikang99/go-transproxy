#!/bin/bash
set -xe

if ! which docker; then
    echo "docker engine not installed"
    exit 1
fi
# Check if we have docker running and accessible
# as the current user
# If not bail out with the default error message
docker ps

_whoami=`whoami`
_goos=`go env GOOS`
_goarch=`go env GOARCH`
DOCKER_ACCOUNT=${DOCKER_ACCOUNT:-$_whoami}
GOOS=${GOOS:-$_goos}
GOARCH=${GOARCH:-$_goarch}
DEB_ARCH=$GOARCH

BUILD_IMAGE=$DOCKER_ACCOUNT/golang-binary-builder
FPM_IMAGE=$DOCKER_ACCOUNT/golang-deb-builder
BUILD_ARTIFACTS_DIR="artifacts"

version=`git rev-parse --short HEAD`
VERSION_STRING="$(cat VERSION)-${version}"


# check all the required environment variables are supplied
[ -z "$BINARY_NAME" ] && echo "Need to set BINARY_NAME" && exit 1;
[ -z "$DEB_PACKAGE_NAME" ] && echo "Need to set DEB_PACKAGE_NAME" && exit 1;
[ -z "$DEB_PACKAGE_DESCRIPTION" ] && echo "Need to set DEB_PACKAGE_DESCRIPTION" && exit 1;

if [ $DEB_ARCH  = "arm" ]; then
  DEB_ARCH="armhf"
fi

rm -rf ./$BUILD_ARTIFACTS_DIR

docker build --build-arg \
    version_string=$VERSION_STRING \
    --build-arg \
    binary_name=$BINARY_NAME \
    --build-arg \
    goos=$GOOS \
    --build-arg \
    goarch=$GOARCH \
    -t $BUILD_IMAGE -f Dockerfile-go .
containerID=$(docker run --detach $BUILD_IMAGE)
docker cp $containerID:/${BINARY_NAME} ./deb/opt/transproxy/
sleep 1
docker rm $containerID

echo "Binary built. Building DEB now."

docker build --build-arg \
    version_string=$VERSION_STRING \
    --build-arg \
    binary_name=$BINARY_NAME \
    --build-arg \
    deb_package_name=$DEB_PACKAGE_NAME  \
    --build-arg \
    deb_package_description="$DEB_PACKAGE_DESCRIPTION" \
    --build-arg \
    deb_arch=$DEB_ARCH \
    -t $FPM_IMAGE -f Dockerfile-fpm .
containerID=$(docker run -dt $FPM_IMAGE)
# docker cp does not support wildcard:
# https://github.com/moby/moby/issues/7710
mkdir -p $BUILD_ARTIFACTS_DIR
docker cp $containerID:/deb-package/${DEB_PACKAGE_NAME}_${VERSION_STRING}_${DEB_ARCH}.deb $BUILD_ARTIFACTS_DIR/.
sleep 1
docker rm -f $containerID

echo "Building DEB SUCCESS!!"
