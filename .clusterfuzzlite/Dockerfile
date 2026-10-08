# ClusterFuzzLite build image for DelegationBench fuzz targets.
# Base image digest pinned for reproducible builds; Dependabot tracks it.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:7c97d379ceb773b0bd345f0ced72b037d26e9bb6c4a0c9a176525e65975c5694

COPY . $SRC/delegationbench
WORKDIR $SRC/delegationbench
COPY .clusterfuzzlite/build.sh $SRC/build.sh
