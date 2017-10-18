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

**NOTE**: On macOS, the `--net=host` parameter is ignored.  You can check the web interface by explicitly mapping ports using the following command, but _DHCP won't work_:

```sh
docker run -p 4000:4000 pluribus-onie-ztp
```

Open the webpage by navigating to http://localhost:4000

*By default, the webserver runs on port 4000.  To change that, pass the
HTTP_PORT environment variable to the run command:*

```sh
docker run --name pluribus-onie-ztp --net=host -e HTTP_PORT=4050 pluribus-onie-ztp
```

After the container is started, `docker start` and `docker stop` can be used to shutdown and boot up the container.

```sh
docker stop pluribus-onie-ztp
docker start pluribus-onie-ztp
```

**NOTE**: `docker run` creates a new container and throws away pre-existing state. `docker stop` and `docker start` re-use the container and maintain state.

## Manage the DHCP server after launching the container

```sh
docker exec pluribius-onie-ztp supervisorctl status dhcpd
docker exec pluribius-onie-ztp supervisorctl start dhcpd
docker exec pluribius-onie-ztp supervisorctl stop dhcpd
```
