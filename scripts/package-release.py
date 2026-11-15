#!/usr/bin/env python3
"""Package already-built binaries with deterministic tar/gzip metadata."""
import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path
import tarfile
import tempfile


def package(binary_dir, output, epoch):
    if epoch < 0:
        raise ValueError("epoch must be nonnegative")
    # Validate the complete pair before writing or replacing an archive.
    binaries = []
    for name in ("own", "own-verify"):
        path = binary_dir / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"not a regular binary: {name}")
        binaries.append((name, path.read_bytes()))
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=output.parent, delete=False) as tmp:
        temporary = Path(tmp.name)
        try:
            with gzip.GzipFile(filename="", mode="wb", fileobj=tmp, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as archive:
                    for name, data in binaries:
                        entry = tarfile.TarInfo(name)
                        entry.size = len(data)
                        entry.mode = 0o755
                        entry.mtime = epoch
                        archive.addfile(entry, io.BytesIO(data))
            tmp.flush()
            os.fsync(tmp.fileno())
            digest = hashlib.sha256(temporary.read_bytes()).hexdigest()
            os.replace(temporary, output)
            output.with_name(output.name + ".sha256").write_text(f"{digest}  {output.name}\n")
        finally:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--epoch", type=int, required=True)
    args = parser.parse_args()
    package(args.binary_dir, args.output, args.epoch)


if __name__ == "__main__":
    main()
