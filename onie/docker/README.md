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
docker run -p 4000:80 pluribus-onie-ztp
```

Open the webpage by navigating to http://localhost:4000
