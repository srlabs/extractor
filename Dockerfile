FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
COPY . /extractor/
RUN apt-get update
#Install tzdata in non-interactive mode, otherwise it asks for timezones.
RUN apt-get install -y --no-install-recommends tzdata
RUN apt-get install -y python3 python3-pip swig
RUN apt-get install -y git android-sdk-libsparse-utils liblz4-tool brotli unrar
RUN apt-get install -y zip rsync
RUN cd /extractor && pip3 install -r requirements.txt
ENTRYPOINT ["/extractor/extractor.py"]
