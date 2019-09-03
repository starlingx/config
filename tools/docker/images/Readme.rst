export VERSION=v1.0.0
sudo docker build \
  --network host \
  -t netcat:${VERSION} \
  .
