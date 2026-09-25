# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile for TON (SMALL form): builds on top of the org C/C++ base image,
# which already provides debian + clang/llvm + libFuzzer + the identities + the build ENV.
#
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) -t ton-commit:test .

FROM ghcr.io/savantenvs/base:20260621

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (available to build.sh); baking it as an ENV breaks clang
# when empty. build.sh unsets it when empty.
ARG SOURCE_DATE_EPOCH
# Undefaulted, so the base's ENV flows through unless a build explicitly overrides it.
ARG SANITIZER_FLAGS
ARG COVERAGE_FLAGS=
ARG MAYHEM_JOBS=

# TON's build needs a few -dev packages the base does not carry. Taking OpenSSL, zlib and
# secp256k1 from the distro (rather than TON's bundled submodules) keeps the image small and
# keeps build.sh off the autotools path for them.
USER root
RUN [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true ; \
    apt-get update && apt-get install -yq --no-install-recommends \
        libssl-dev zlib1g-dev libsecp256k1-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
USER mayhem

# Source enters from the build CONTEXT (the CI checkout): the FULL repo, including .git
# history, is copied to /mayhem; build.sh builds in place.
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

# TON keeps several dependencies as git submodules. A fresh `actions/checkout` (and the
# conformance gate's clean clone of HEAD) carries the gitlinks but not their contents, so
# materialise exactly the ones this integration needs — nothing here is fetched again by
# build.sh, which must run offline.
#   crc32c, tl-parser   add_subdirectory()'d unconditionally: CMake cannot even configure
#                       without them.
#   lz4, libbacktrace   tdutils links both.
#   sodium, blst        ton_crypto (the oracle's test-cells) links both.
# Submodule working trees are TRACKED paths, so rlenv's pre-build `git clean -ffdX` (which
# only removes IGNORED files) leaves them in place and the graded offline rebuild still works.
RUN git -c protocol.version=2 submodule update --init --depth 1 \
        third-party/crc32c \
        third-party/tl-parser \
        third-party/lz4 \
        third-party/libbacktrace \
        third-party/sodium \
        third-party/blst

# Anything a Dockerfile step materializes into the tree must be committed or (re)created by
# build.sh — rlenv's patch grader runs `git clean -ffdX` before every graded build.
RUN bash mayhem/build.sh

# The project's functional tests run at build time: a failing suite fails the image build.
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
