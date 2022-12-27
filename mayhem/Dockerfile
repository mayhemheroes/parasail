FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential automake libtool

COPY . /repo
WORKDIR /repo
RUN autoreconf -fi
RUN ./configure --prefix=/install
RUN make -j8
RUN make install

FROM ubuntu:20.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libgomp1
COPY --from=builder /install /install
