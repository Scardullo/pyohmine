#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import pwd
import grp
import shutil
import stat
import sys
import tarfile
import tempfile
import threading
import time
import traceback
import fnmatch
import re
from datetime import datetime, timezone
from email.policy import default
from typing import Any, Dict, Generator, Iterable, List, Optional, Tuple


try:
    from inotify_simple import INotify, flags as inotify_flags
    HAVE_INOTIFY = True
except Exception:
    HAVE_INOTIFY = False


DEFAULT_MAX_READ = 1024 * 1024 * 5
HASH_CHUNK = 1024 * 64
CSV_FIELDS = ["path", "inode", "mode", "nlink", "uid", "size", "atime", "mtime", "ctime"]


def human_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    for unit in ["KiB", "MiB", "GiB", "TiB"]:
        n /= 1024.0
        if n < 1024.0:
            return f"{n:.1f} {unit}"
    return f"{n:.1f} PiB"


def safe_join(base: str, *paths: str) -> str:
    candidate = os.path.normpath(os.path.join(base, *paths))
    if os.path.commonpath([base]) != os.path.commonpath([base, candidate]):
        raise ValueError(f"path {candidate!r} escapes base {base!r}")
    return candidate


def file_stat_dict(path: str) -> Dict[str, Any]:
    st = os.lstat(path)
    return {
        "path": path,
        "inode": st.st_ino,
        "mode": st.st_mode,
        "nlink": st.st_nlink,
        "uid": st.st_uid,
        "gid": st.st_gid,
        "size": st.st_size,
        "atime": datetime.fromtimestamp(st.st_atime, tz=timezone.utc).isoformat(),
        "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
        "ctime": datetime.fromtimestamp(st.st_ctime, tz=timezone.utc).isoformat(),
    }


def compute_hash(path: str, algorithm: str = "sha256") -> str:
    algo = algorithm.lower()
    if algo == "md5":
        hasher = hashlib.md5()
    elif algo == "sha1":
        hasher = hashlib.sha1()
    elif algo == "sha256":
        hasher = hashlib.sha256()
    else:
        raise ValueError("unsupported hash algorithim: %r" % algorithm)
    with open(path, "rb") as f:  # rb = read binary
        while True:
            chunk = f.read(HASH_CHUNK)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()  # <- hash value written in hex


class FileEntry:

    __slots__ = ("path", "name", "is_file", "is_dir", "is_symlink", "stat", "size")

    def __init__(self, path: str):
        self.path = path
        self.name = os.path.basename(path)
        self.is_symlink = os.path.islink(path)
        self.is_file = os.path.isfile(path)
        self.is_dir = os.path.isdir(path)
        try:
            self.stat = os.lstat(path)
            self.size = self.stat.st_size
        except FileNotFoundError:
            self.stat = None
            self.size = 0

    def to_dict(self) -> Dict[str, Any]:
        if self.stat is None:
            return {"path": self.path, "exists": False}
        return {
            "path": self.path,
            "name": self.name,
            "is_file": self.is_file,
            "is_dir": self.is_dir,
            "is_symlink": self.is_symlink,
            "inode": self.stat.st_ino,
            "mode": self.stat.st_mode,
            "size": self.size,
        }


def walk_tree(
    root: str,
    follow_symlinks: bool = False,
    ignore_patterns: Optional[Iterable[str]] = None,
) -> Generator[FileEntry, None, None]:
    if ignore_patterns is None:
        ignore_patterns = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        dirnames[:] = [d for d in dirnames if not any(fnmatch.fnmatch(d, pat) for pat in ignore_patterns)]
        for name in dirnames + filenames:
            if any(fnmatch.fnmatch(name, pat) for pat in ignore_patterns):
                continue
            full = os.path.join(dirpath, name)
            yield FileEntry(full)


def search_by_name(root: str, pattern: str) -> List[str]:
    matches = []
    for entry in walk_tree(root):
        if fnmatch.fnmatch(entry.name, pattern):
            matches.append(entry.path)
    return matches


def search_by_regex(root: str, pattern: str) -> List[str]:
    regex = re.compile(pattern)
    matches = []
    for entry in walk_tree(root):
        if regex.search(entry.name):
            matches.append(entry.path)
    return matches


def search_by_size(root: str, min_size: Optional[int] = None, max_size: Optional[int] = None) -> List[str]:
    matches = []
    for entry in walk_tree(root):
        if not entry.is_file:
            continue
        if min_size is not None and entry.size < min_size:
            continue
        if max_size is not None and entry.size:
            continue
        matches.append(entry.path)
    return matches


def read_text_file(path: str, max_bytes: int = DEFAULT_MAX_READ, errors: str = "replace") -> str:
    with open(path, "rb") as f:
        data = f.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"file too large: {path!r}, > {max_bytes} bytes")
    return data.decode("utf-8", errors=errors)


def read_binary_file(path: str, max_bytes: int = DEFAULT_MAX_READ) -> bytes:
    with open(path, "rb") as f:
        data = f.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"file too large: {path!r}, > {max_bytes} bytes")
    return data


def atomic_write(path: str, data: bytes, mode: int = 0o644) -> None:
    dirpath = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(dir=dirpath)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except Exception:
            pass
        raise


def append_atomic(path: str, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    fd = os.open(path, flags, 0o644)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)

def copy_file(src: str, dst: str, follow_symlinks: bool = False) -> None:
    shutil.copy2(src, dst, follow_symlinks=follow_symlinks)


def move_file(src: str, dst: str,) -> None:
    shutil.move(src, dst)


def make_symlink(target: str, link_name: str) -> None:
    os.symlink(target, link_name)


def make_hardlink(target: str, link_name: str) -> None:
    os.link(target, link_name)


def safe_remove(path: str) -> None:
    if os.path.islink(path) or os.path.isfile(path):
        os.unlink(path)
    elif os.path.isdir(path):
        shutil.rmtree(path)
    else:
        if os.path.exists(path):
            raise FileNotFoundError(path)


def chmod(path: str, mode: int) -> None:
    os.chmod(path, mode)

def chown(path: str, uid: Optional[int] = None, gid: Optional[int] = None) -> None:
    if uid is None and gid is None:
        return
    os.chown(path, -1 if uid is None else uid, -1 if gid is None else gid)


def parse_symbolic_mode(sym: str) -> int:
    mode = 0
    for part in sym.split(","):
        who, perms = part.split("=")
        mask = 0
        if "r" in perms:
            mask |= stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
        if "w" in perms:
            mask |= stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
        if "x" in perms:
            mask |= stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        bits = 0
        if "u" in who:
            bits |= (mask & (stat.S_IRWXU))
        if "g" in who:
            bits |= (mask & (stat.S_IRWXG))
        if "o" in who:
            bits |= (mask &(stat.S_IRWXO))
        mode |= bits
    return mode


def create_tar_backup(root: str, tar_path: str, compress: bool = True) -> None:
    mode = "w:gz" if compress else "w"
    with tarfile.open(tar_path, mode) as tar:
        tar.add(root, arcname=os.path.basename(root))


def list_tar_contents(tar_path: str) -> List[str]:
    with tarfile.open(tar_path, "r:*") as tar:
        return tar.getnames()


def extract_tar(tar_path: str, dest: str) -> None:
    with tarfile.open(tar_path, "r:*") as tar:
        tar.extractall(dest)


def find_duplicates(root: str, algorithm: str = "sha256") -> Dict[str, List[str]]:
    mapping: Dict[str, List[str]] = {}
    for entry in walk_tree(root):
        if not entry.is_file:
            continue
        try:
            h = compute_hash(entry.path, algorithm=algorithm)
        except Exception:
            continue
        mapping.setdefault(h, []).append(entry.path)
    return {h: paths for h, paths in mapping.items() if len(paths) > 1}


class Watcher:

    def __init__(self, paths: Iterable[str], recursive: bool = True, poll_interval: float = 1.0):
        self.paths = list(paths)
        self.recursive = recursive
        self.poll_interval = poll_interval
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._snapshot: Dict[str, float] = {}
        if HAVE_INOTIFY:
            self._inotify = INotify()
            self._wd_to_path: Dict[int, str] = {}
        else:
            self._inotify = None

    def _build_snapshot(self) -> None:
        snap: Dict[str, float] = {}
        for p in self.paths:
            if os.path.isfile(p):
                try:
                    snap[p] = os.path.getmtime(p)
                except Exception:
                    pass
            elif os.path.isdir(p):
                for entry in walk_tree(p):
                    try:
                        snap[entry.path] = os.path.getmtime(entry.path)
                    except Exception:
                        pass
        self._snapshot = snap

    def _poll_loop(self, callback):
        self._build_snapshot()
        while self._running:
            time.sleep(self.poll_interval)
            new_snap: Dict[str, float] = {}
            for p in self.paths:
                if os.path.isfile(p):
                    try:
                        new_snap[p] = os.path.getmtime(p)
                    except Exception:
                        pass
                elif os.path.isdir(p):
                    for entry in walk_tree(p):
                        try:
                            new_snap[entry.path] = os.path.getmtime(entry.path)
                        except Exception:
                            pass

            old_keys = set(self._snapshot)
            new_keys = set(new_snap)
            added = new_keys - old_keys
            removed = old_keys - new_keys
            common = old_keys & new_keys
            modified = [k for k in common if new_snap[k] != self._snapshot[k]]
            for a in added:
                callback("created", a)
            for r in removed:
                callback("removed", r)
            for m in modified:
                callback("modified", m)
            self._snapshot = new_snap

    def start(self, callback):
        if HAVE_INOTIFY:
            for p in self.paths:
                if os.path.exists(p):
                    wd = self._inotify.add_watch(p, inotify_flags.CREATE | inotify_flags.DELETE | inotify_flags.MODIFY | inotify_flags.MOVE_SELF)
                    self._wd_to_path[wd] = p
            self._running = True
            self._thread = threading.Thread(target=self._inotify_loop, args=(callback,), daemon=True)
            self._thread.start()
        else:
            self._running = True
            self._thread = threading.Thread(target=self._poll_loop, args=(callback,), daemon=True)
            self._thread.start()

    def _inotify_loop(self, callback):
        assert self._inotify is not None
        while self._running:
            for event in self._inotify.read(timeout=1000):
                wd = event.wd
                name = event.name
                base = self._wd_to_path.get(wd, None)
                full = os.path.join(base, name) if base else name
                if inotify_flags.MODIFY in inotify_flags.from_mask(event.mask):
                    callback("modified", full)
                elif inotify_flags.CREATE in inotify_flags.from_mask(event.mask):
                    callback("created", full)
                elif inotify_flags.DELETE in inotify_flags.from_mask(event.maks):
                    callback("removed", full)
                elif inotify_flags.MOVE_SELF in inotify_flags.from_mask(event.mask):
                    callback("moved", full)

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None
        if HAVE_INOTIFY and self._inotify is not None:
            for wd in list(self._wd_to_path.keys()):
                try:
                    self._inotify.rm_watch(wd)
                except Exception:
                    pass


def export_tree_csv(root: str, csv_path: str) -> None:
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for entry in walk_tree(root):
            try:
                row = file_stat_dict(entry.path)
            except Exception:
                continue
            writer.writerow({k: row.get(k, "") for k in CSV_FIELDS})


def export_tree_json(root: str, json_path: str) -> None:
    all_entries = []
    for entry in walk_tree(root):
        try:
            all_entries.append(file_stat_dict(entry.path))
        except Exception:
            continue
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(all_entries, fh, indent=2)


def repl(start_dir: str = ".") -> None:
    """
        Commands:
        ls [path]          - list directory entries
        cat <path>         - print short preview of file
        stat <path>        - print stat JSON
        hash <path>        - print sha256
        exit               - quit
    """
    cwd = os.path.abspath(start_dir)
    print("REPL = Read → Eval → Print → Loop")
    print("Type 'help' for commands, 'exit' to quit")
    while True:
        try:
            line = input(f"fs> ")
        except EOFError:
            print()
            break
        if not line:
            continue
        parts = line.split()
        if not parts:
            continue
        cmd = parts[0]
        args = parts[1:]
        try:
            if cmd == "help":
                print(repl.__doc__)
            elif cmd == "cd":
                if not args:
                    print(cwd)
                else:
                    try:
                        new = os.path.abspath(os.path.join(cwd, args[0]))
                        if os.path.isdir(new):
                            cwd = new
                        else:
                            print("not a directory")
                    except Exception as e:
                        print("error:", e)
            elif cmd == "ls":
                target = cwd if not args else os.path.join(cwd, args[0])
                try:
                    for name in os.listdir(target):
                        print(name)
                except Exception as e:
                    print("error:", e)
            elif cmd == "cat":
                if not args:
                    print("usage: cat <path>")
                else:
                    target = os.path.join(cwd, args[0])
                    try:
                        preview = read_text_file(target, max_bytes=2048)
                        print(preview)
                    except Exception as e:
                        print("error:", e)
            elif cmd == "stat":
                if not args:
                    print("usage: stat <path>")
                else:
                    target = os.path.join(cwd, args[0])
                    try:
                        print(json.dumps(file_stat_dict(target), indent=2))
                    except Exception as e:
                        print("error:", e)
            elif cmd == "hash":
                if not args:
                    print("usage: hash <path>")
                else:
                    target = os.path.join(cwd, args[0])
                    try:
                        print(compute_hash(target))
                    except Exception as e:
                        print("error:", e)
            elif cmd == "exit" or cmd == "quit":
                break
            else:
                print("unknown command, cmd")
        except Exception:
            traceback.print_exc()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Filesystem Tools (single-file)")
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("list", help="list files")
    sp.add_argument("root", nargs="?", default=".")
    sp.add_argument("--json", help="output JSON file")
    sp.add_argument("--csv", help="output CSV file")

    sp = sub.add_parser("search", help="search by name or regex")
    sp.add_argument("root", nargs="?", default=".")
    sp.add_argument("--name", help="glob pattern, e.g. '*.py'")
    sp.add_argument("--regex", help="regex applied to filenames")

    sp = sub.add_parser("cat", help="cat file")
    sp.add_argument("path")
    sp.add_argument("--bytes", type=int, default=2048)

    sp = sub.add_parser("hash", help="compute file hash")
    sp.add_argument("path")
    sp.add_argument("--algo", default="sha256", choices=["md5", "sha1", "sha256"])

    sp = sub.add_parser("export", help="export tree metadata to CSV/JSON")
    sp.add_argument("root", nargs="?", default=".")
    sp.add_argument("--csv")
    sp.add_argument("--json")

    sp = sub.add_parser("dupes", help="find duplicates by hash")
    sp.add_argument("root", nargs="?", default=".")
    sp.add_argument("--algo", default="sha256", choices=["md5", "sha1", "sha256"])

    sp = sub.add_parser("backup", help="create tar gz backup")
    sp.add_argument("root")
    sp.add_argument("out", help="output tar.gz path")

    sub.add_parser("repl", help="start interactive REPL")

    sp = sub.add_parser("watch", help="watch a path for changes (polling fallback")
    sp.add_argument("paths", nargs="+")
    sp.add_argument("--poll", type=float, default=1.0)

    sub.add_parser("test", help="run included unit tests")

    return p


def main(argv: Optional[List[str]] = None) -> int:
    p = build_parser()
    args = p.parse_args(argv)
    if args.cmd == "list":
        if args.json:
            export_tree_json(args.root, args.json)
            print("wrote json to", args.json)
        if args.csv:
            export_tree_csv(args.root, args.csv)
            print("wrote csv to", args.csv)
        if not args.csv and not args.json:
            for entry in walk_tree(args.root):
                print(entry.path)
        return 0
    if args.cmd == "search":
        if args.name:
            matches = search_by_name(args.root, args.name)
            for m in matches:
                print(m)
            return 0
        if args.regex:
            matches = search_by_regex(args.root, args.regex)
            for m in matches:
                print(m)
            return 0
        print("provide --name or --regex")
        return 2
    if args.cmd == "cat":
        try:
            print(read_text_file(args.path, max_bytes=args.bytes))
        except Exception as e:
            print("error:", e)
            return 1
        return 0
    if args.cmd == "hash":
        try:
            print(compute_hash(args.path, algorithm=args.algo))
        except Exception as e:
            print("error:", e)
            return 1
        return 0
    if args.cmd == "export":
        if args.csv:
            export_tree_csv(args.root, args.csv)
            print("CSV written to", args.csv)
        if args.json:
            export_tree_json(args.root, args.json)
            print("json written to", args.json)
        return 0
    if args.cmd == "dupes":
        mapping = find_duplicates(args.root, algorithim=args.algo)
        for h,paths in mapping.items():
            print(h)
            for p in paths:
                print(" ", p)
        return 0
    if args.cmd == "backup":
        create_tar_backup(args.root, args.out, compress=True)
        print("backup created:", args.out)
        return 0
    if args.cmd == "repl":
        repl()
        return 0
    if args.cmd == "watch":
        def cb(evt, pth):
            print(f"[{datetime.now().isoformat()}] {evt}: {pth}")
        w = Watcher(args.paths, poll_interval=args.poll)
        w.start(cb)
        try:
            print("wathcing (ctrl-c to stop) ...")
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("stopping...")
            w.stop()
        return 0
    if args.cmd =="test":
        import unittest

        loader = unittest.TestLoader()
        tests = loader.loadTestsFromName("fs_study_tool_tests")
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(tests)
        return 0 if result.wasSuccessful() else 1
    p.print_help()
    return 0


import unittest

class FSStudyTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="fsstudy_test_")
        self.dir_a = os.path.join(self.tmpdir, "a_dir")
        self.dir_b = os.path.join(self.tmpdir, "b_dir")
        os.mkdir(self.dir_a)
        os.mkdir(self.dir_b)
        with open(os.path.join(self.dir_a, "one.txt"), "w") as f:
            f.write("hello world\n")
        with open(os.path.join(self.dir_b, "two.txt"), "w") as f:
            f.write("goodbye world\n")
        with open(os.path.join(self.tmpdir, "dup1.bin"), "wb") as f:
            f.write(b"dupdata")
        with open(os.path.join(self.tmpdir, "dup2.bin"), "wb") as f:
            f.write(b"dupdata")
        try:
            os.symlink(os.path.join(self.dir_a, "one.txt"), os.path.join(self.tmpdir, "link_one"))
        except Exception:
            pass

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_walk_tree(self):
        seen = list(walk_tree(self.tmpdir))
        self.assertTrue(any(e.name == "one.txt" for e in seen))
        self.assertTrue(any(e.name == "two.txt" for e in seen))

    def test_search_name(self):
        res = search_by_name(self.tmpdir, "*.txt")
        self.assertTrue(any(p.endswith("one.txt") for p in res))

    def test_search_regex(self):
        res = search_by_regex(self.tmpdir, r"two\.txt")
        self.assertTrue(any(p.endswith("two.txt") for p in res))

    def test_read_write(self):
        path = os.path.join(self.tmpdir, "write_test.txt")
        atomic_write(path, b"abc\n")
        data = read_text_file(path)
        self.assertIn("abc", data)
        append_atomic(path, b"more\n")
        data2 = read_text_file(path)
        self.assertIn("more", data2)

    def test_hash(self):
        h = compute_hash(os.path.join(self.dir_a, "one.txt"), algorithm="md5")
        self.assertIsInstance(h, str)

    def test_dupes(self):
        d = find_duplicates(self.tmpdir, algorithm="sha256")
        found = False
        for paths in d.values():
            if any("dup1.bin" in p for p in paths) and any("dup2.bin" in p for p in paths):
                found = True
        self.assertTrue(found)

    def test_backup_and_list(self):
        tarpath = os.path.join(self.tmpdir, "bk.tar.gz")
        create_tar_backup(self.tmpdir, tarpath, compress=True)
        names = list_tar_contents(tarpath)
        self.assertTrue(len(names) > 0)

fs_study_tool_tests = FSStudyTests

if __name__ == "__main__":
    sys.exit(main())
    

