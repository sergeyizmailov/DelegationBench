#!/bin/bash -eu
# ClusterFuzzLite build script: installs the package and packages every
# fuzz target under fuzz/ as a standalone executable in $OUT.

pip3 install .

cd "$SRC/delegationbench"

for fuzzer in $(find fuzz -maxdepth 1 -name 'fuzz_*.py'); do
  fuzzer_basename=$(basename -s .py "$fuzzer")
  fuzzer_package="${fuzzer_basename}.pkg"

  # Package the fuzzer as a standalone binary so it keeps working even if
  # the Python environment changes.
  pyinstaller --distpath "$OUT" --onefile --name "$fuzzer_package" "$fuzzer"

  # Execution wrapper. Atheris needs the sanitizer runtime preloaded;
  # PyYAML ships a C extension, so keep the preload. The first comment is
  # load-bearing: ClusterFuzzLite discovers fuzz targets by scanning for
  # the LLVMFuzzerTestOneInput string.
  cat > "$OUT/${fuzzer_basename}" <<EOF
#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer.
this_dir=\$(dirname "\$0")
LD_PRELOAD=\$this_dir/sanitizer_with_fuzzer.so \
  ASAN_OPTIONS=\$ASAN_OPTIONS:detect_leaks=0 \
  \$this_dir/$fuzzer_package "\$@"
EOF
  chmod +x "$OUT/${fuzzer_basename}"

  # Ship the seed corpus next to the fuzzer when one exists.
  if [ -d "fuzz/corpora/${fuzzer_basename}" ]; then
    (cd "fuzz/corpora/${fuzzer_basename}" && \
      zip -q -r "$OUT/${fuzzer_basename}_seed_corpus.zip" .)
  fi
done
