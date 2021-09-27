FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
#Install tzdata in non-interactive mode, otherwise it asks for timezones.
RUN apt-get install -y --no-install-recommends tzdata
RUN apt-get install -y python3 python3-pip swig
RUN apt-get install -y git android-sdk-libsparse-utils liblz4-tool brotli unrar p7zip-full
RUN apt-get install -y zip rsync
RUN apt-get install -y default-jdk  # Required for "jar" utility, helps with some broken zip files
RUN apt-get install -y python2 python-is-python2  # Required for splituapp and kdzextractor
RUN apt-get install -y zlib1g-dev  # Required for compiling sinextract
COPY . /extractor/
RUN cd /extractor/sinextract && make -j4
RUN cd /extractor && pip3 install -r requirements.txt
ENTRYPOINT ["/extractor/extractor.py"]
