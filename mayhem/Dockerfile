FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential apt-transport-https curl gnupg python3 clang

RUN curl -fsSL https://bazel.build/bazel-release.pub.gpg | gpg --dearmor > bazel.gpg
RUN mv bazel.gpg /etc/apt/trusted.gpg.d/
RUN echo "deb [arch=amd64] https://storage.googleapis.com/bazel-apt stable jdk1.8" | tee /etc/apt/sources.list.d/bazel.list
RUN apt update && apt install -y bazel

COPY . /repo
WORKDIR /repo
RUN bazel build glslangValidator
RUN bazel build glslang
RUN clang++ /repo/mayhem/fuzz_isBuiltInSymbol.cpp -fsanitize=fuzzer,address -I /repo/glslang/MachineIndependent/ -o /fuzz -L /repo/bazel-bin/ -lglslang

FROM ubuntu:22.04 as package
COPY --from=builder /repo/bazel-bin/glslangValidator /
COPY --from=builder /fuzz /fuzz_isBuiltInSymbol
