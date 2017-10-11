# ONIE ZTP Docker Image

## Build the image

```sh
docker build -t pluribus-onie-ztp .
```

Or if you'd rather not clone the repo to build the image:

```sh
docker build -t pluribus-onie-ztp 'https://github.com/amitsi/onieztp.git#:onie/docker'
```

## Run the image

```sh
docker run --net=host pluribus-onie-ztp
```

Open the webpage by navigating to http://localhost:4000

*By default, the webserver runs on port 4000.  To change that, pass the
HTTP_PORT environment variable to the run command:*

```sh
docker run --net=host -e HTTP_PORT=4050 pluribus-onie-ztp
```

## Manage the DHCP server after launching the container

```sh
CONTAINER=$( docker ps --format '{{.ID}} {{.Image}}' | awk '$2 == "pluribus-onie-ztp" { print $1 }' )

docker exec ${CONTAINER:-NOTRUNNING} supervisorctl status dhcpd
docker exec ${CONTAINER:-NOTRUNNING} supervisorctl start dhcpd
docker exec ${CONTAINER:-NOTRUNNING} supervisorctl stop dhcpd
```
