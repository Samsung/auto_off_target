FROM python:3.8-slim as aot_deps

WORKDIR /tmp
COPY src/requirements.txt .
RUN pip install --upgrade pip \
    && pip wheel --no-cache-dir --wheel-dir /tmp/wheels -r requirements.txt


FROM ubuntu:20.04 as cas_build

ENV DEBIAN_FRONTEND="noninteractive"
ENV PATH=/tools/bin:$PATH

WORKDIR /tmp
COPY docker/*.sh /tools/bin/

RUN apt-get -qq update --quiet \
    && apt-get -qq -y install --no-install-suggests --no-install-recommends \
        bison \
        build-essential \
        clang-11 \
        clang-format-11 \
        clang-tidy-11 \
        clang-tools-11 \
        cmake \
        flex \
        gcc-9-plugin-dev \
        libclang-dev \
        libssl-dev \
        llvm-11 \
        llvm-11-dev \
        llvm-11-tools \
        python-futures \
        python3-dev \
        unzip \
        wget \
    && update-clang.sh 11 50 \
    && rm -rf /var/lib/apt/lists/*
    
RUN mkdir -p CAS-master/build \
    && wget --no-check-certificate -O CAS-master.zip "https://github.com/Samsung/CAS/archive/master.zip" \
    && unzip -q CAS-master.zip \
    && cd CAS-master/build \
    && cmake -DCMAKE_BUILD_TYPE=Release .. \
    && cmake --build . -- -j10 ftdb \
    && strip libftdb.so


FROM ubuntu:20.04 as main

ENV DEBIAN_FRONTEND="noninteractive"
ENV PATH=/tools/aot:/tools/bin:$PATH
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

COPY --from=aot_deps /tmp/wheels /tools/wheels
COPY src /tools/aot
COPY --from=cas_build /tmp/CAS-master/build/libftdb.so /tools/aot/libs/
COPY docker/*.sh /tools/bin/

RUN apt-get -qq update --quiet \
    && apt-get -qq -y install --no-install-suggests --no-install-recommends \
        bash-completion \
        build-essential \
        clang-11 \
        clang-9 \
        clang-format-11 \
        clang-format-9 \
        clang-tidy-11 \
        clang-tidy-9 \
        clang-tools-11 \
        clang-tools-9 \
        curl \
        gdb \
        libboost-program-options1.71.0 \
        libgoogle-perftools4 \
        libpython3.8 \
        libsqlite3-0 \
        libz3-4 \
        lld-11 \
        lldb-11 \
        llvm-11 \
        llvm-11-dev \
        llvm-11-tools \
        llvm-9 \
        llvm-9-dev \
        llvm-9-tools \
        mc \
        minisat \
        python-is-python3 \
        python3-pip \
        python3.8 \
        unzip \
        valgrind \
        vim \
        wget \
        xxd \
        zip \
    && ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm \
    && update-clang.sh 9 40 \
    && update-clang.sh 11 50 \
    && rm -rf /var/lib/apt/lists/*
    
RUN pip install --no-index --find-links=/tools/wheels -r /tools/aot/requirements.txt \
    && adduser --system --group --home /app aotuser

ENV PYTHONPATH=/tools/aot/libs

WORKDIR /app
USER aotuser
COPY docs /app/docs

ENTRYPOINT [ "/tools/aot/aot.py" ]
