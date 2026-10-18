"""Release assets are built from the tag, not from the checkout.

The fork's release pipeline is ``.github/workflows/release.yml``:

  * a manual ``workflow_dispatch`` carrying one required ``version`` input;
  * the full ``tests.yml`` matrix runs first (``needs: test``);
  * the ``release`` job bumps ``VERSION`` in ``app/wb_proxy.py`` exactly once,
    commits it to main, creates ``v<version>`` and publishes the GitHub
    Release with generated notes (pre-release for ``-rc`` style versions);
  * ``docker-publish.yml`` builds the image and ``package.yml`` builds the
    green package, both from that tag.

``package.yml`` runs ``tools/_build_green_package.py`` on Windows: the ZIP is
a ``git archive`` of the tagged tree plus the pinned official embeddable
CPython (``python/``), and it is attached to the Release. The assertions below
pin those promises locally, so a release cannot ship a working-tree snapshot,
a runtime that cannot start the gateway, or a package missing ``app/web``.

The portable-ZIP helper in ``release/`` is the explicit-manifest builder (the
``release/portable.txt`` list is what the updater replaces). It is exercised
against this fork's ``app/`` layout: every source and dashboard file has to be
listed, the archive has to carry the runtime marker, and a rebuild has to be
byte-identical.

Run with: python tests/_test_release_assets.py
"""
import ast
import glob
import hashlib
import importlib.util
import os
import re
import sys
import tempfile
import unittest
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "release"))

import matrix_legs  # noqa: E402
import portable_runtime  # noqa: E402
import release_tools as tools  # noqa: E402

# The legs the repository has to keep running for a release today. The gate
# reads them from tests.yml rather than from this tuple - this is the
# expectation the reader checks that derivation against.
EXPECTED_LEGS = (
    "ubuntu-latest / python 3.9",
    "ubuntu-latest / python 3.12",
    "windows-latest / python 3.12",
)


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def load_green_builder():
    """Import tools/_build_green_package.py without running its main()."""
    path = os.path.join(ROOT, "tools", "_build_green_package.py")
    spec = importlib.util.spec_from_file_location("build_green_package", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_runtime(directory, extra=()):
    """A stand-in runtime that satisfies portable_runtime.verify()."""
    for rel in list(portable_runtime.REQUIRED_FILES) + list(extra):
        path = os.path.join(directory, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(b"stub:" + rel.encode("utf-8"))
    return directory


# ---- release-writer scanner ------------------------------------------------
#
# A release mutation is a command the workflow actually *runs*: one that sits at
# command position, either on its own line inside a `run: |` block, after a
# one-line `run:`, or behind a shell separator. A step that merely prints the
# same command inside an echo must not be flagged - command position is what
# separates "runs it" from "talks about it".
#
# `gh api` is the subtle half. It defaults to GET, but *any* field flag turns
# the request into a POST, so `gh api repos/o/r/releases -f tag_name=v1` creates
# a release without ever naming a method. Only an explicit `-X GET` /
# `--method GET` says the call is a read.

# `gh release <verb>` - the four verbs that change a release.
GH_RELEASE_WRITE = re.compile(r"^gh\s+release\s+(?:create|edit|upload|delete)\b")
GH_API = re.compile(r"^gh\s+api\b")
# `-X POST`, `-XPOST`, `--method POST`, `--method=POST`.
API_METHOD = re.compile(r"(?:^|\s)(?:-X|--method)(?:[=\s]*)([A-Za-z]+)")
# Flags that make gh send a body, which is what flips the default to POST.
API_BODY_FLAG = re.compile(r"(?:^|\s)(?:-f|-F|--field|--raw-field|--input)(?:=|\s|$)")

# Fragments a shell command can be split into. Pipes are left alone on purpose:
# splitting on `|` would slice through quoted strings for no gain here.
SHELL_SEPARATOR = re.compile(r"&&|\|\||;")
# A one-line step carries its command after `run:` (possibly as a list item).
INLINE_RUN = re.compile(r"^(?:-\s*)?run:\s*")


def shell_commands(text):
    """Logical shell commands in a workflow, with `\\` continuations joined.

    Only line continuations are normalised - this is not a shell parser and
    does not try to be one.
    """
    joined, buf = [], ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        joined.append(buf + line)
        buf = ""
    if buf:
        joined.append(buf)

    for line in joined:
        for piece in SHELL_SEPARATOR.split(line):
            piece = INLINE_RUN.sub("", piece.strip())
            if piece:
                yield piece


def is_release_mutation(command):
    """Would running this command change a GitHub Release?"""
    if GH_RELEASE_WRITE.match(command):
        return True
    if not GH_API.match(command):
        return False
    method = API_METHOD.search(command)
    if method:
        return method.group(1).upper() != "GET"
    return bool(API_BODY_FLAG.search(command))


def release_mutations(text):
    """The release-mutating commands a piece of workflow text runs."""
    return [c for c in shell_commands(text) if is_release_mutation(c)]


def workflow_jobs(text):
    """{job id: job text} for the top-level `jobs:` mapping of a workflow."""
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.rstrip() == "jobs:":
            start = i
            break
    if start is None:
        return {}
    jobs, current, buf = {}, None, []
    for line in lines[start + 1:]:
        if not line.strip():
            if current:
                buf.append(line)
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0:
            break
        if indent == 2 and not line.lstrip().startswith("#") and line.rstrip().endswith(":"):
            if current:
                jobs[current] = "\n".join(buf)
            current = line.strip()[:-1]
            buf = []
            continue
        if current is not None:
            buf.append(line)
    if current:
        jobs[current] = "\n".join(buf)
    return jobs


def dispatch_input_names(text):
    """Input names declared under `on.workflow_dispatch.inputs`."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip() != "workflow_dispatch:":
            continue
        parent = len(line) - len(line.lstrip())
        for j in range(i + 1, len(lines)):
            cur = lines[j]
            if not cur.strip() or cur.lstrip().startswith("#"):
                continue
            indent = len(cur) - len(cur.lstrip())
            if indent <= parent:
                break
            if cur.strip() != "inputs:":
                continue
            names = []
            for nxt in lines[j + 1:]:
                if not nxt.strip() or nxt.lstrip().startswith("#"):
                    continue
                nind = len(nxt) - len(nxt.lstrip())
                if nind <= indent:
                    break
                if nind == indent + 2 and nxt.strip().endswith(":"):
                    names.append(nxt.strip()[:-1])
            return names
    return []


def release_writer_jobs(text):
    """Jobs that run at least one release-mutating command."""
    return sorted(name for name, body in workflow_jobs(text).items()
                  if release_mutations(body))


# The only job allowed to touch the Release, and the only input a dispatch may
# take. The writer is authorised by `needs: test`, which is the reusable
# tests.yml workflow - a manual run cannot skip it.
RELEASE_WRITER_JOB = "release"
DISPATCH_INPUTS = ["version"]


def check_release_writers(text):
    """Raise AssertionError unless the release contract below still holds.

    The fork publishes from a manual dispatch (there is no tag-push trigger),
    so the safety property is not "only a tag push may write": it is that the
    one writer job waits for the full test workflow, owns `contents: write`,
    and that the dispatch offers nothing but the version number.
    """
    jobs = workflow_jobs(text)
    writers = release_writer_jobs(text)
    assert writers, "没找到任何 release 写入点——检查器本身失效了，不是工作流变干净了"
    assert writers == [RELEASE_WRITER_JOB], (
        "只有 %s 这一个 job 可以写 release，实际是 %s"
        % (RELEASE_WRITER_JOB, writers))
    body = jobs[RELEASE_WRITER_JOB]
    assert re.search(r"(?m)^\s*needs:\s*test\s*$", body), (
        "release job 必须依赖 test（reusable tests.yml），否则可以绕过测试发版")
    assert "contents: write" in body, (
        "release job 需要 contents: write 才能提交版本号、打标签、建 Release")
    inputs = dispatch_input_names(text)
    assert inputs == DISPATCH_INPUTS, (
        "workflow_dispatch 只能有 version 一个输入，实际是 %s" % inputs)


class ManifestTests(unittest.TestCase):
    """release/portable.txt is the authoritative list of packaged files."""

    def test_every_listed_path_exists(self):
        for name in tools.read_manifest():
            self.assertTrue(os.path.isfile(os.path.join(ROOT, name)),
                            "清单里的 %s 不存在" % name)

    def test_every_application_file_is_listed(self):
        # The regression this list exists for: a new module (or a dashboard
        # asset under app/web) that nobody remembered to add would otherwise
        # be missing from the portable package, and the launcher would fail
        # with ModuleNotFoundError / a blank panel on a user's machine.
        on_disk = []
        for base, dirs, files in os.walk(os.path.join(ROOT, "app")):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for name in files:
                rel = os.path.relpath(os.path.join(base, name), ROOT)
                on_disk.append(rel.replace(os.sep, "/"))
        self.assertTrue(on_disk, "仓库里没有 app/ 源码？")
        listed = set(tools.read_manifest())
        self.assertEqual(sorted(p for p in on_disk if p not in listed), [])

    def test_launchers_and_dashboard_are_listed(self):
        listed = tools.read_manifest()
        for name in ("dashboard.html", "app/wb_proxy.py", "README.md", "LICENSE",
                     "start-wb-proxy.bat", "start-wb-proxy.sh",
                     "start-wb-proxy.command", "start-wb-proxy-lan.sh"):
            self.assertIn(name, listed)

    def test_every_launcher_script_is_listed(self):
        """启动脚本按前缀全量扫：漏登记一个就在这儿红。

        #285 的教训：portable.txt 里 start-wb-proxy-lan.bat 被 restart-wb-proxy.bat
        顶掉了，而新脚本恰恰要调用它——便携包少了这个文件，Windows 的 LAN 启动与
        重启都会失败。上面那份手写清单只点了 .sh 的名，所以没拦住。
        quick-deploy.sh 是 Docker 路径、刻意不进便携包，不在前缀里。
        """
        listed = tools.read_manifest()
        for prefix in ("start-wb-proxy", "restart-wb-proxy", "allow-firewall"):
            for path in sorted(glob.glob(os.path.join(ROOT, prefix + "*"))):
                name = os.path.basename(path)
                if name.endswith((".bat", ".sh", ".command")):
                    self.assertIn(name, listed, "便携包清单缺少 %s" % name)

    def test_runtime_data_files_are_listed(self):
        # wb_pricing._candidate_file() prefers pricing/pricing.json over the
        # copy inlined in the module, so a package without it silently ships
        # older prices than the release it came from.
        self.assertIn("pricing/pricing.json", tools.read_manifest())

    def test_entries_are_relative_and_inside_the_repo(self):
        for name in tools.read_manifest():
            self.assertFalse(os.path.isabs(name), name)
            self.assertNotIn("..", name.split("/"), name)
            self.assertNotIn("\\", name, name)

    def test_no_duplicates(self):
        listed = tools.read_manifest()
        self.assertEqual(len(listed), len(set(listed)))

    def test_user_data_directories_are_not_managed_files(self):
        # The updater replaces exactly the managed files and must leave
        # accounts/ and usage/ byte-for-byte alone, so no manifest entry may
        # live inside them.
        for name in tools.read_manifest():
            for protected in tools.PROTECTED:
                self.assertFalse(name.startswith(protected),
                                 "%s 落在受保护目录 %s 里" % (name, protected))

    def test_development_only_files_stay_out(self):
        listed = tools.read_manifest()
        for name in ("Dockerfile", "docker-compose.yml", "quick-deploy.sh",
                     "tests/run_all.py", "tools/_build_green_package.py"):
            self.assertNotIn(name, listed)


class RuntimeTrimTests(unittest.TestCase):
    """The trim rules reproduce the runtime the portable package ships."""

    def test_the_app_modules_survive_the_trim(self):
        # Every stdlib module the gateway imports has to be in the contract
        # list, or the trim could drop the thing it depends on.
        imported = set()
        for path in glob.glob(os.path.join(ROOT, "app", "wb_*.py")):
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(a.name.split(".")[0] for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    imported.add(node.module.split(".")[0])
        local = {os.path.basename(p)[:-3]
                 for p in glob.glob(os.path.join(ROOT, "app", "*.py"))}
        # sys / time and friends are compiled into python312.dll, so the trim
        # cannot remove them and they have no Lib/ file to check.
        needed = sorted(m for m in imported
                        if m not in local and m not in sys.builtin_module_names)
        self.assertTrue(needed)
        covered = set(portable_runtime.REQUIRED_FILES)
        missing = [m for m in needed
                   if ("Lib/%s.py" % m) not in covered
                   and ("Lib/%s/__init__.py" % m) not in covered]
        self.assertEqual(missing, [], "这些导入没有出现在运行时常量表里：%s" % missing)

    def test_the_documented_trim_is_exactly_what_goes(self):
        for rel in ("Lib/multiprocessing", "Lib/tkinter/__init__.py", "Lib/idlelib/idle.py",
                    "Lib/site-packages/pip/__init__.py", "Lib/venv/__init__.py",
                    "Scripts/pip.exe", "include/Python.h", "libs/python312.lib",
                    "tcl/tk8.6/init.tcl", "pythonw.exe", "python312.pdb",
                    "DLLs/_tkinter.pyd", "DLLs/tcl86t.dll", "DLLs/tk86t.dll",
                    "DLLs/zlib1.dll", "DLLs/_testcapi.pyd", "Lib/__pycache__/os.cpython-312.pyc"):
            self.assertFalse(portable_runtime.keep(rel), "%s 应该被裁掉" % rel)

    def test_what_the_launchers_need_survives(self):
        for rel in ("python.exe", "python3.dll", "python312.dll", "vcruntime140.dll",
                    "LICENSE.txt", "Lib/os.py", "Lib/ssl.py", "Lib/sqlite3/__init__.py",
                    "DLLs/_socket.pyd", "DLLs/_ssl.pyd", "DLLs/libssl-3-x64.dll",
                    "DLLs/_ctypes.pyd", "DLLs/libffi-8.dll"):
            self.assertTrue(portable_runtime.keep(rel), "%s 不能被裁掉" % rel)

    def test_verify_rejects_a_runtime_that_cannot_start_the_gateway(self):
        with tempfile.TemporaryDirectory(prefix="relrt-") as directory:
            make_runtime(directory)
            portable_runtime.verify(directory)          # the fixture is valid

            os.remove(os.path.join(directory, "python.exe"))
            with self.assertRaises(SystemExit):
                portable_runtime.verify(directory)

    def test_verify_rejects_trimmed_files_coming_back(self):
        with tempfile.TemporaryDirectory(prefix="relrt-") as directory:
            make_runtime(directory)
            os.makedirs(os.path.join(directory, "Lib", "multiprocessing"))
            with self.assertRaises(SystemExit):
                portable_runtime.verify(directory)

    def test_verify_rejects_stray_debug_symbols(self):
        with tempfile.TemporaryDirectory(prefix="relrt-") as directory:
            make_runtime(directory, extra=["DLLs/_socket.pdb"])
            with self.assertRaises(SystemExit):
                portable_runtime.verify(directory)


class PortableZipTests(unittest.TestCase):
    # The version comes from the checkout, not a literal: a release tool that
    # refused to build after a version bump would be a tool nobody trusts, and
    # a test pinned to yesterday's number would hide that.
    VERSION = tools.source_version(ROOT)
    TAG = "v" + VERSION

    def build(self, directory, name="out.zip", runtime=None, **kwargs):
        runtime = runtime or make_runtime(os.path.join(directory, "python"))
        return tools.build_portable(self.VERSION, self.TAG,
                                    os.path.join(directory, name),
                                    source=ROOT, runtime_dir=runtime, **kwargs)

    def test_archive_holds_the_manifest_the_runtime_and_the_marker(self):
        with tempfile.TemporaryDirectory(prefix="relzip-") as directory:
            path, files = self.build(directory)
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
            root = tools.PACKAGE_ROOT
            self.assertEqual(sorted(n for n in names if not n.startswith(root + "/")),
                             [tools.MANIFEST_NAME])
            self.assertEqual(sorted(n[len(root) + 1:] for n in names if n.startswith(root + "/")
                                    and not n.startswith(root + "/python/")),
                             sorted(files))
            self.assertIn("%s/python/python.exe" % root, names)
            self.assertIn("%s/python/Lib/os.py" % root, names)

    def test_the_archive_is_not_a_source_archive(self):
        # The whole point of the round-1 fix: a ZIP without the runtime is a
        # different, much less useful asset, so the builder must not produce it.
        with tempfile.TemporaryDirectory(prefix="relzip-") as directory:
            path, _ = self.build(directory)
            runtime_files = [n for n in zipfile.ZipFile(path).namelist()
                             if n.endswith("python/python.exe")]
            self.assertEqual(len(runtime_files), 1)

    def test_a_missing_runtime_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="relzip-") as directory:
            with self.assertRaises(SystemExit):
                tools.build_portable(self.VERSION, self.TAG,
                                     os.path.join(directory, "x.zip"), source=ROOT,
                                     runtime_dir=None)
            with self.assertRaises(SystemExit):
                tools.build_portable(self.VERSION, self.TAG,
                                     os.path.join(directory, "x.zip"), source=ROOT,
                                     runtime_dir=os.path.join(directory, "nope"))

    def test_a_runtime_that_fails_the_contract_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="relzip-") as directory:
            bad = make_runtime(os.path.join(directory, "bad"))
            os.remove(os.path.join(bad, "python.exe"))
            with self.assertRaises(SystemExit):
                tools.build_portable(self.VERSION, self.TAG,
                                     os.path.join(directory, "x.zip"), source=ROOT,
                                     runtime_dir=bad)

    def test_embedded_manifest_describes_the_release(self):
        import json
        with tempfile.TemporaryDirectory(prefix="relzip-") as directory:
            path, files = self.build(directory)
            with zipfile.ZipFile(path) as zf:
                manifest = json.loads(zf.read(tools.MANIFEST_NAME).decode("utf-8"))
            self.assertEqual(manifest["files"], files)
            self.assertEqual(manifest["protected"], tools.PROTECTED)
            self.assertEqual(manifest["root"], tools.PACKAGE_ROOT)
            self.assertEqual(manifest["version"], tools.source_version(ROOT))
            self.assertEqual(manifest["tag"], self.TAG)
            # The updater replaces the runtime as one subtree, so the manifest
            # has to name it instead of leaving it implicit.
            self.assertEqual(manifest["runtime"]["prefix"], "python/")
            self.assertEqual(manifest["runtime"]["python"], portable_runtime.RUNTIME_VERSION)
            self.assertGreater(manifest["runtime"]["files"], 0)

    def test_the_launchers_look_where_the_runtime_is(self):
        # The packaged path and the path the launcher probes have to agree, or
        # the package silently falls back to a system interpreter.
        bat = read("start-wb-proxy.bat")
        self.assertIn("python\\python.exe", bat)
        self.assertIn("app\\wb_proxy.py", bat)
        sh = read("start-wb-proxy.sh")
        self.assertIn("python/bin/python3", sh)
        self.assertIn("app/wb_proxy.py", sh)

    def test_the_archive_root_matches_the_green_package(self):
        # Two builders, one product: extracting either asset gives the same
        # top-level folder, so launchers and the update path agree.
        self.assertEqual(tools.PACKAGE_ROOT, load_green_builder().PACKAGE_ROOT)
        self.assertEqual(tools.PACKAGE_ROOT, "wb-proxy-center")

    def test_archive_paths_are_safe(self):
        with tempfile.TemporaryDirectory(prefix="relzip-") as directory:
            path, _ = self.build(directory)
            with zipfile.ZipFile(path) as zf:
                for name in zf.namelist():
                    self.assertFalse(name.startswith("/"), name)
                    self.assertNotIn("..", name.split("/"), name)

    def test_rebuild_is_byte_identical(self):
        with tempfile.TemporaryDirectory(prefix="relzip-") as directory:
            runtime = make_runtime(os.path.join(directory, "python"))
            first, _ = self.build(directory, "a.zip", runtime=runtime)
            second, _ = self.build(directory, "b.zip", runtime=runtime)
            with open(first, "rb") as fa, open(second, "rb") as fb:
                self.assertEqual(fa.read(), fb.read())

    def test_version_mismatch_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="relzip-") as directory:
            runtime = make_runtime(os.path.join(directory, "python"))
            with self.assertRaises(SystemExit):
                tools.build_portable("9.9.9", "v9.9.9",
                                     os.path.join(directory, "x.zip"), source=ROOT,
                                     runtime_dir=runtime)


class ChecksumTests(unittest.TestCase):
    def test_covers_every_asset_once_in_sha256sum_format(self):
        with tempfile.TemporaryDirectory(prefix="relsum-") as directory:
            names = [tools.asset_names("0.2.0"), tools.asset_names("0.2.0-rc.1")]
            assets = []
            for i, name in enumerate(names):
                p = os.path.join(directory, name)
                with open(p, "wb") as fh:
                    fh.write(b"asset-%d" % i)
                assets.append(p)
            out = os.path.join(directory, "checksums.txt")
            lines = tools.write_checksums(assets, out)
            self.assertEqual(len(lines), len(names))
            for line, path in zip(lines, sorted(assets, key=os.path.basename)):
                digest, name = line.split("  ")
                self.assertEqual(len(digest), 64)
                self.assertEqual(name.strip(), os.path.basename(path))
                with open(path, "rb") as fh:
                    self.assertEqual(digest, hashlib.sha256(fh.read()).hexdigest())

    def test_hash_follows_the_bytes(self):
        with tempfile.TemporaryDirectory(prefix="relsum-") as directory:
            p = os.path.join(directory, "a.zip")
            with open(p, "wb") as fh:
                fh.write(b"one")
            before = tools.sha256(p)
            with open(p, "wb") as fh:
                fh.write(b"two")
            self.assertNotEqual(before, tools.sha256(p))


class ReleaseBodyTests(unittest.TestCase):
    block = None

    def setUp(self):
        self.zip_name = tools.asset_names("0.2.0")
        self.block = tools.download_block(self.zip_name)

    def test_first_compose_has_the_marker_and_the_fixed_block(self):
        body = tools.compose_body("", self.block)
        self.assertIn(tools.MARKER, body)
        for expected in ("## 下载说明", "wb-proxy-center-v0.2.0.zip", "checksums.txt"):
            self.assertIn(expected, body)

    def test_maintainer_notes_above_the_marker_survive(self):
        notes = "## 本版要点\n\n- 修了一个真问题\n"
        body = tools.compose_body(notes + "\n" + tools.MARKER + "\n旧块\n", self.block)
        self.assertIn("- 修了一个真问题", body)
        self.assertNotIn("旧块", body)

    def test_recompose_is_idempotent(self):
        once = tools.compose_body("", self.block)
        twice = tools.compose_body(once, self.block)
        self.assertEqual(once, twice)
        self.assertEqual(twice.count(tools.MARKER), 1)


class MatrixLegsTests(unittest.TestCase):
    """The release gate names every leg instead of trusting a summary."""

    def test_the_repository_matrix_is_the_expected_three(self):
        self.assertEqual(tuple(matrix_legs.legs()), EXPECTED_LEGS)

    def test_dropping_a_leg_narrows_what_the_gate_requires(self):
        # Deriving the legs from tests.yml is the point: if a leg disappears
        # there, the gate stops waiting for it - and the unit above is what
        # makes that a deliberate change rather than a silent weakening.
        text = read(".github", "workflows", "tests.yml")
        without = text.replace('          - os: windows-latest\n            python: "3.12"\n', "")
        self.assertNotEqual(without, text, "tests.yml 里没有找到预期的 windows 腿")
        self.assertEqual(tuple(matrix_legs.legs(without)), EXPECTED_LEGS[:2])

    def test_an_unparseable_matrix_yields_nothing(self):
        # Empty means "the gate must refuse", never "no legs to check".
        self.assertEqual(matrix_legs.legs("name: tests\njobs:\n  test:\n    runs-on: x\n"), [])


class ReleaseToolingTests(unittest.TestCase):
    def test_the_tools_survive_a_non_utf8_console(self):
        # The Windows runner's stdout is cp1252, and the first Chinese progress
        # line aborted the first rehearsal of this workflow - the repository
        # already paid for the same lesson in tests/run_all.py. Every tool pins
        # its own streams instead of trusting the console.
        for name in ("release/portable_runtime.py", "release/release_tools.py",
                     "tools/_build_green_package.py"):
            self.assertIn('reconfigure(encoding="utf-8"', read(*name.split("/")), name)

    def test_the_test_workflow_pins_utf8_for_every_python_process(self):
        self.assertIn('PYTHONUTF8: "1"', read(".github", "workflows", "tests.yml"))

    def test_the_green_package_job_runs_the_pinned_builder(self):
        package = read(".github", "workflows", "package.yml")
        self.assertIn("python tools/_build_green_package.py", package)
        self.assertIn("runs-on: windows-latest", package)


class ReleaseMutationScannerTests(unittest.TestCase):
    """The command shapes the scanner has to classify, and how.

    Kept as a table so the contract is readable: everything in WRITES must be
    caught, everything in READS must not be. `gh api` is the interesting half -
    it defaults to GET, but any body flag turns the call into a POST.
    """

    WRITES = (
        "gh release create \"$TAG\" --draft",
        "gh release edit \"$TAG\" --draft",
        "gh release upload \"$TAG\" dist/*.zip --clobber",
        "gh release delete \"$TAG\" --yes",
        "gh api repos/o/r/releases -X POST -f tag_name=v1",
        "gh api -XPOST repos/o/r/releases",
        "gh api --method PATCH repos/o/r/releases/1",
        "gh api --method=DELETE repos/o/r/releases/1",
        "gh api repos/o/r/releases -f tag_name=v1",
        "gh api repos/o/r/releases -F tag_name=@body.json",
        "gh api repos/o/r/releases --field tag_name=v1",
        "gh api repos/o/r/releases --raw-field tag_name=v1",
        "gh api repos/o/r/releases --input body.json",
    )
    READS = (
        "gh release view \"$TAG\" --json body",
        "gh release list --limit 5",
        "gh api repos/o/r/releases",
        "gh api -X GET repos/o/r/releases -f per_page=1",
        "gh api --method=GET repos/o/r/releases",
        "gh api --method GET repos/o/r/releases/tags/$TAG",
        "echo \"gh release create $TAG --draft\"",
        "python release/release_tools.py checksums --out dist/checksums.txt",
        "git push --force-with-lease origin main",
    )

    def test_every_writing_shape_is_a_mutation(self):
        for command in self.WRITES:
            self.assertTrue(is_release_mutation(command), command)

    def test_every_read_only_shape_is_not_a_mutation(self):
        for command in self.READS:
            self.assertFalse(is_release_mutation(command), command)

    def test_continuations_are_joined_before_the_decision(self):
        text = ("        run: |\n"
                "          gh api \\\n"
                "            repos/o/r/releases \\\n"
                "            -f tag_name=v1\n")
        found = release_mutations(text)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].split(),
                         ["gh", "api", "repos/o/r/releases", "-f", "tag_name=v1"])

    def test_a_shell_separator_does_not_hide_a_command(self):
        text = "        run: true && gh release delete \"$TAG\" --yes\n"
        self.assertEqual(release_mutations(text), ["gh release delete \"$TAG\" --yes"])

    def test_an_echo_of_a_command_is_not_a_mutation(self):
        text = "        run: |\n          echo \"gh release create $TAG --draft\"\n"
        self.assertEqual(release_mutations(text), [])

    def test_the_real_workflow_only_writes_from_one_job(self):
        text = read(".github", "workflows", "release.yml")
        self.assertEqual(release_writer_jobs(text), ["release"])
        self.assertTrue(release_mutations(workflow_jobs(text)["release"]))


class ReleaseWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = read(".github", "workflows", "release.yml")
        self.jobs = workflow_jobs(self.text)

    def test_triggers_on_a_manual_dispatch_with_one_version_input(self):
        self.assertIn("workflow_dispatch:", self.text)
        self.assertEqual(dispatch_input_names(self.text), ["version"])
        self.assertNotIn("\n  push:", self.text)
        dispatch = self.text.split("on:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertIn("required: true", dispatch)

    def test_the_version_is_normalised_and_validated_before_any_write(self):
        step = self.text.split("- name: Validate version", 1)[1]
        step = step.split("- uses: actions/checkout", 1)[0]
        self.assertIn('V="${VERSION_INPUT#v}"', step)
        self.assertIn(r'^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$', step)
        self.assertIn("版本号格式无效", step)
        self.assertIn("exit 1", step)
        # The tag, the value and the pre-release flag all come from this one
        # validated variable.
        self.assertIn('echo "value=$V"', step)
        self.assertIn('echo "tag=v$V"', step)
        self.assertIn("prerelease=true", step)
        self.assertIn("prerelease=false", step)
        self.assertLess(self.text.index("Validate version"),
                        self.text.index("Bump VERSION"))

    def test_the_version_is_bumped_in_the_app_entrypoint(self):
        # app/wb_proxy.py is the single source of truth: VERSION drives
        # server_version and the /health payload. The workflow refuses to bump
        # when the definition is not exactly one line.
        self.assertIn("""grep -c '^VERSION = "' app/wb_proxy.py""", self.text)
        self.assertIn('''sed -i "s/^VERSION = \\"[^\\"]*\\"/VERSION = \\"$VALUE\\"/" app/wb_proxy.py''',
                      self.text)
        self.assertIn("git add app/wb_proxy.py", self.text)
        self.assertIn('git commit -m "release: $TAG"', self.text)
        self.assertIn("git push origin HEAD:main", self.text)

    def test_the_tag_is_free_and_created_after_the_bump(self):
        self.assertIn("git ls-remote --exit-code --tags origin", self.text)
        self.assertIn("标签 $TAG 已存在", self.text)
        self.assertLess(self.text.index("Ensure the tag is free"),
                        self.text.index("Bump VERSION"))
        self.assertIn('git tag -a "$TAG" -m "$TAG"', self.text)
        self.assertIn('git push origin "$TAG"', self.text)
        self.assertLess(self.text.index("Bump VERSION"),
                        self.text.index('git tag -a "$TAG"'))

    def test_the_release_is_published_with_generated_notes(self):
        self.assertIn('gh release create "$TAG" --verify-tag --title "$TAG" '
                      '--generate-notes', self.text)
        self.assertIn('if [ "$PRERELEASE" = "true" ]; then', self.text)
        self.assertIn("--prerelease", self.text)
        # The fork publishes directly; there is no draft stage or manual
        # publish step that could leave a release invisible.
        self.assertNotIn("--draft", self.text)

    def test_the_release_job_waits_for_the_test_workflow(self):
        self.assertIn("uses: ./.github/workflows/tests.yml", self.jobs["test"])
        self.assertRegex(self.jobs["release"], r"(?m)^\s*needs:\s*test\s*$")
        self.assertIn("contents: write", self.jobs["release"])

    def test_downstream_jobs_consume_the_created_tag(self):
        self.assertIn("tag: ${{ steps.version.outputs.tag }}", self.jobs["release"])
        image = self.jobs["publish-image"]
        self.assertIn("uses: ./.github/workflows/docker-publish.yml", image)
        self.assertIn("tag: ${{ needs.release.outputs.tag }}", image)
        package = self.jobs["package"]
        self.assertIn("uses: ./.github/workflows/package.yml", package)
        self.assertIn("tag: ${{ needs.release.outputs.tag }}", package)

    def test_only_the_release_job_can_write_a_release(self):
        check_release_writers(self.text)
        self.assertEqual(release_writer_jobs(self.text), [RELEASE_WRITER_JOB])

    # ---- negative evidence: the checker has to be able to fail -------------
    #
    # A checker that cannot fail proves nothing. Each mutation below is a real
    # way the contract could regress; the suite is the thing that notices.

    def test_the_checker_rejects_a_writer_outside_the_release_job(self):
        mutated = self.text.replace(
            "  release:\n",
            "  sneak:\n    runs-on: ubuntu-latest\n    steps:\n"
            "    - run: gh release delete \"$TAG\" --yes\n\n  release:\n", 1)
        self.assertNotEqual(mutated, self.text)
        with self.assertRaises(AssertionError):
            check_release_writers(mutated)

    def test_the_checker_rejects_a_release_without_the_test_gate(self):
        mutated = self.text.replace("    needs: test\n", "", 1)
        self.assertNotEqual(mutated, self.text)
        with self.assertRaises(AssertionError):
            check_release_writers(mutated)

    def test_the_checker_rejects_a_dispatch_input_that_could_gate_a_write(self):
        mutated = self.text.replace(
            "    inputs:\n      version:\n",
            "    inputs:\n      version:\n      dry_run:\n        description: \"x\"\n", 1)
        self.assertNotEqual(mutated, self.text)
        with self.assertRaises(AssertionError):
            check_release_writers(mutated)

    def test_the_checker_rejects_a_one_line_write_in_the_test_job(self):
        # The short form is just as much a writer as the block form.
        mutated = self.text.replace(
            "    uses: ./.github/workflows/tests.yml\n",
            "    steps:\n    - run: gh release delete \"$TAG\" --yes\n"
            "    uses: ./.github/workflows/tests.yml\n", 1)
        self.assertNotEqual(mutated, self.text)
        with self.assertRaises(AssertionError):
            check_release_writers(mutated)

    def test_the_checker_rejects_an_implicit_post_that_creates_a_release(self):
        # gh defaults to POST as soon as a field flag is there, so this line
        # creates a release without ever naming a method.
        mutated = self.text.replace(
            "    uses: ./.github/workflows/tests.yml\n",
            "    steps:\n    - run: |\n"
            "        gh api \"repos/$GH_REPO/releases\" -f tag_name=\"$TAG\" -f draft=true\n"
            "    uses: ./.github/workflows/tests.yml\n", 1)
        self.assertNotEqual(mutated, self.text)
        self.assertIn("-f tag_name=", mutated)
        with self.assertRaises(AssertionError):
            check_release_writers(mutated)

    def test_the_checker_rejects_an_implicit_post_split_over_continuations(self):
        mutated = self.text.replace(
            "    uses: ./.github/workflows/tests.yml\n",
            "    steps:\n    - run: |\n"
            "        gh api \\\n"
            "          \"repos/$GH_REPO/releases\" \\\n"
            "          --field tag_name=\"$TAG\" \\\n"
            "          --raw-field draft=true\n"
            "    uses: ./.github/workflows/tests.yml\n", 1)
        self.assertNotEqual(mutated, self.text)
        with self.assertRaises(AssertionError):
            check_release_writers(mutated)

    def test_the_checker_rejects_a_write_split_over_continuations(self):
        mutated = self.text.replace(
            "    uses: ./.github/workflows/tests.yml\n",
            "    steps:\n    - run: |\n"
            "        gh release \\\n          create \"$TAG\" --draft\n"
            "    uses: ./.github/workflows/tests.yml\n", 1)
        self.assertNotEqual(mutated, self.text)
        with self.assertRaises(AssertionError):
            check_release_writers(mutated)

    def test_the_checker_accepts_a_read_only_api_call_anywhere(self):
        # The other half of the contract: an explicit GET stays legal even when
        # it carries fields. A scanner that flagged this would push people to
        # weaken the check instead of fixing it.
        synthetic = (
            "name: synthetic\n"
            "on:\n"
            "  workflow_dispatch:\n"
            "    inputs:\n"
            "      version:\n"
            "        description: x\n"
            "        required: true\n"
            "jobs:\n"
            "  release:\n"
            "    needs: test\n"
            "    permissions:\n"
            "      contents: write\n"
            "    steps:\n"
            "    - run: gh release create \"$TAG\" --verify-tag\n"
            "    - run: gh api -X GET \"repos/$GH_REPO/releases\" -f per_page=1\n"
            "    - run: gh api --method=GET \"repos/$GH_REPO/releases/tags/$TAG\"\n")
        check_release_writers(synthetic)
        self.assertEqual(release_writer_jobs(synthetic), [RELEASE_WRITER_JOB])

    def test_the_checker_notices_when_it_finds_no_writer_at_all(self):
        mutated = self.text
        for verb in ("create", "edit", "upload"):
            mutated = mutated.replace("gh release %s" % verb, "true ")
        self.assertNotEqual(mutated, self.text)
        with self.assertRaises(AssertionError):
            check_release_writers(mutated)


class GreenPackageTests(unittest.TestCase):
    """tools/_build_green_package.py is the asset the Release actually carries."""

    def setUp(self):
        self.builder = load_green_builder()
        self.source = read("tools", "_build_green_package.py")
        self.package = read(".github", "workflows", "package.yml")

    def test_the_builder_packages_the_tagged_tree(self):
        # `git archive <ref>` packages exactly what the tag points at; copying
        # the working tree would ship uncommitted edits (and miss deletions).
        self.assertIn('["git", "archive", "--format=tar"', self.source)
        self.assertIn('f"--output={tree}", args.ref', self.source)
        self.assertIn("ref: ${{ inputs.tag || github.event.release.tag_name }}",
                      self.package)

    def test_the_runtime_is_the_pinned_embeddable_distribution(self):
        self.assertRegex(self.builder.PYTHON_VERSION, r"^\d+\.\d+\.\d+$")
        self.assertEqual(
            self.builder.RUNTIME_URL,
            "https://www.python.org/ftp/python/%s/python-%s-embed-amd64.zip"
            % (self.builder.PYTHON_VERSION, self.builder.PYTHON_VERSION))
        self.assertRegex(self.builder.RUNTIME_SHA256, r"^[0-9a-f]{64}$")
        # The digest is verified before anything is extracted.
        self.assertIn("digest = sha256(archive)", self.source)
        self.assertIn("if digest != RUNTIME_SHA256", self.source)
        self.assertIn("raise SystemExit", self.source)

    def test_the_isolated_mode_pth_is_removed(self):
        # The embeddable distribution's ._pth puts Python into isolated mode:
        # sys.path follows that file only, so app/ imports fail until it is
        # deleted. Its name has to track the runtime version.
        major_minor = "".join(self.builder.PYTHON_VERSION.split(".")[:2])
        self.assertEqual(self.builder.PTH_NAME, "python%s._pth" % major_minor)
        self.assertIn("(runtime / PTH_NAME).unlink()", self.source)

    def test_the_archive_layout_matches_the_launchers(self):
        self.assertEqual(self.builder.PACKAGE_ROOT, "wb-proxy-center")
        self.assertIn('f"{PACKAGE_ROOT}-v{args.version}.zip"', self.source)
        self.assertIn('f"{PACKAGE_ROOT}/{path.relative_to(staging).as_posix()}"',
                      self.source)
        bat = read("start-wb-proxy.bat")
        self.assertIn("app\\wb_proxy.py", bat)
        self.assertIn("python\\python.exe", bat)
        sh = read("start-wb-proxy.sh")
        self.assertIn("app/wb_proxy.py", sh)
        self.assertIn("python/bin/python3", sh)

    def test_the_package_workflow_builds_and_attaches_the_zip(self):
        self.assertIn("release:\n    types: [published]", self.package)
        self.assertIn("workflow_call:\n    inputs:\n      tag:", self.package)
        self.assertIn("workflow_dispatch:\n    inputs:\n      tag:", self.package)
        self.assertIn("runs-on: windows-latest", self.package)
        # The version comes from the tag, never a second hand-maintained
        # literal that could disagree with it.
        self.assertIn("value=${TAG#v}", self.package)
        self.assertIn('python tools/_build_green_package.py --version '
                      '"${{ steps.version.outputs.value }}" --out dist',
                      self.package)
        self.assertIn("path: dist/*.zip", self.package)
        self.assertIn('gh release view "$TAG"', self.package)
        self.assertIn('gh release upload "$TAG" dist/*.zip --clobber', self.package)

    def test_the_release_pipeline_calls_the_green_package_job(self):
        jobs = workflow_jobs(read(".github", "workflows", "release.yml"))
        package = jobs["package"]
        self.assertIn("uses: ./.github/workflows/package.yml", package)
        self.assertIn("tag: ${{ needs.release.outputs.tag }}", package)

    def test_user_data_cannot_reach_the_archive(self):
        # git archive only sees tracked files, and the updater's protected
        # directories are gitignored - so a release can never carry accounts/
        # or usage/ from the maintainer's machine.
        ignored = read(".gitignore")
        for pattern in ("accounts/*.json", "usage/*.jsonl"):
            self.assertIn(pattern, ignored)


if __name__ == "__main__":
    unittest.main()
