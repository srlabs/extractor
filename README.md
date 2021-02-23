# Extractor &middot; [![GitHub license](https://img.shields.io/badge/license-Apache%202.0-blue)](#LICENSE)

<p align="center">
  <img src="/docs/media/ext.png">
</p>

Extractor is a powerful Android firmware image extraction utility

## Supported formats

Extractor supports the following Android image formats:
```
android sparse image, erofs, extfs, android signed images, android data image, android data image brotli, pac, zip, lz4, tar, tar md5, sin, ozip, app, kdz, bin, cpb, super
```

# Installation
To run Extractor on your computer some preparation steps are necessary. Since Extractor is a python tool, a working python environment is required.

## Debian-based (Debian, Ubuntu)

Currently supports Debian 10 and Ubuntu 20.04. Use a terminal shell to execute the following commands:

```bash
sudo apt update
# Install dependencies
sudo apt install -y git android-sdk-libsparse-utils liblz4-tool brotli unrar
```

We recommend using a python virtualenv for installing Extractors python dependencies:

```bash
# Create virtualenv in venv directory
python3 -m venv venv
# Activate virtualenv
source venv/bin/activate
```

Now, install the python dependencies:

```bash
pip3 install -r requirements.txt
```

Extractor depends on some git submodules, all of which can be initialized like so

```bash
# Initialize git submodules
./scripts/init.sh
```

If you wish to run Extractor without installing the necesarry requirements yourself, you may run it using docker.

# Usage

You can run Extractor on your machine by running:

```bash
sudo ./extractor.py <firmware image> --system-dir-output <output directory>
```

This will extract a firmware image into a specified output directory. Extractor also supports saving the output in a tar archive:

```bash
sudo ./extractor.py <firmware image> --tar-output
```

Note: root privileges are required due to temporarily active loopback mount operations

## Docker

```bash
./extract-docker.py --in-file <firmware image> --out-dir <output directory>
```

## License

Extractor is [Apache 2.0 licensed](LICENSE).