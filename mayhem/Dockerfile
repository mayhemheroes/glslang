FROM --platform=linux/amd64 ubuntu:22.04 AS builder

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential cmake ninja-build python3 clang

COPY . /repo
WORKDIR /repo/build
RUN cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
RUN ninja glslangValidator glslang

RUN clang++ /repo/mayhem/fuzz_isBuiltInSymbol.cpp \
    -fsanitize=fuzzer,address \
    -I /repo/glslang/MachineIndependent/ \
    -o /fuzz \
    -L /repo/build/glslang \
    -lglslang

FROM ubuntu:22.04 AS package
COPY --from=builder /repo/build/StandAlone/glslangValidator /
COPY --from=builder /fuzz /fuzz_isBuiltInSymbol
