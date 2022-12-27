FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential automake libtool clang

COPY . /repo
WORKDIR /repo
RUN autoreconf -fi
RUN ./configure --prefix=/install
RUN make -j8
RUN make install
RUN clang++ /repo/mayhem/fuzz_parasail_matrix_create.cpp -fsanitize=fuzzer,address -I /install/include/ /install/lib/libparasail.a -o /fuzz

FROM ubuntu:20.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libgomp1
COPY --from=builder /install /install
COPY --from=builder /fuzz /fuzz_parasail_matrix_create
