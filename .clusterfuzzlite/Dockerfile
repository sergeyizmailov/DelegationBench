# ClusterFuzzLite build image for DelegationBench fuzz targets.
# Base image digest pinned for reproducible builds; Dependabot tracks it.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:662ca248430ff29e82f3505caa17e3b75f118243a41cfa42ae64fd24ef6365f0

COPY . $SRC/delegationbench
WORKDIR $SRC/delegationbench
COPY .clusterfuzzlite/build.sh $SRC/build.sh
