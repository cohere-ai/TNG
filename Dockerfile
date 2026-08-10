FROM alibaba-cloud-linux-3-registry.cn-hangzhou.cr.aliyuncs.com/alinux3/alinux3:latest AS builder

# replace mirrors
RUN sed -i -E 's|https?://mirrors.cloud.aliyuncs.com/|https://mirrors.aliyun.com/|g' /etc/yum.repos.d/*.repo

# install build dependencies
RUN yum install -y git protobuf-devel gcc curl clang perl openssl-devel

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --no-modify-path --default-toolchain none

WORKDIR /code/

COPY rust-toolchain.toml .

# install toolchain and cache it
RUN . "$HOME/.cargo/env" && rustup show

COPY . .

RUN . "$HOME/.cargo/env" && env RUSTFLAGS="--cfg tokio_unstable" cargo install --locked --path ./tng/ --root /usr/local/cargo/


FROM alibaba-cloud-linux-3-registry.cn-hangzhou.cr.aliyuncs.com/alinux3/alinux3:latest AS release

# replace mirrors
RUN sed -i -E 's|https?://mirrors.cloud.aliyuncs.com/|https://mirrors.aliyun.com/|g' /etc/yum.repos.d/*.repo

RUN yum install -y curl iptables iproute openssl && yum clean all
RUN yum reinstall -y ca-certificates

COPY --from=builder /usr/local/cargo/bin/tng /usr/local/bin/tng

CMD ["tng"]
