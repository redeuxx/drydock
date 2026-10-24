"""Restore apply against real daemons: the wipe helper, put_archive and host-path resolution.

The host daemon (through the socket proxy) covers volumes. Host paths need a filesystem
the test can change, so those tests use the sshhost dind daemon, whose host filesystem is
the sshhost container. Each test uses its own helper instance ID, so concurrent runs never
see each other's helpers, and labels what else it creates drydock.test.
"""

import contextlib
import tarfile
import threading
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import docker.errors
import pytest
from docker.types import Mount

from drydock.config import DEFAULT_HELPER_IMAGE
from drydock.engine import stream_probe
from drydock.hosts import client as docker_client
from drydock.hosts import helper
from drydock.restore import apply
from drydock.restore import plan as p
from drydock.restore.verify import InnerTarGuard, MemberFacts
from drydock.security import hostpaths
from drydock.security.hostpaths import HostPathError
from tests.docker_support import TEST_LABEL, helpers_left, host_docker, needs_docker, sh, sshhost
from tests.restore_support import TarEntry, inner_tar
from tests.test_capture import PLAIN_URL, needs_dind

IMAGE = DEFAULT_HELPER_IMAGE
# Runs as root with Docker's default capabilities (it must chown); test only, never a helper.
STICKY_SETUP = """
set -e
mkdir -p /v/tmp/sub/deeper /v/private
printf x > /v/tmp/other && chown 1001:1001 /v/tmp/other && chmod 0600 /v/tmp/other
chown -R 1002:1002 /v/tmp/sub
chown 1000:1000 /v/tmp && chmod 1777 /v/tmp
printf y > /v/private/secret && chmod 0600 /v/private/secret
chown -R 1003:1003 /v/private && chmod 0700 /v/private
mkdir /v/rootonly && chmod 0700 /v/rootonly && printf z > /v/rootonly/f
"""


def instance() -> str:
    return f"drydocktest{uuid.uuid4().hex[:8]}"


def make_plan(**changes: Any) -> p.RestorePlan:
    fields: dict[str, Any] = {
        "mode": "overwrite",
        "host_id": 1,
        "images": (),
        "networks": (),
        "volumes": (),
        "originals": (),
        "wipes": (),
        "data": (),
        "containers": (),
        "risk": (),
        "warnings": (),
        "lock_keys": (),
        "bind_sources": (),
        "write_targets": (),
    } | changes
    return p.RestorePlan(**fields)


class StaticReader:
    """Stands in for restore.verify.ArchiveReader with members held in memory."""

    def __init__(self, members: dict[str, bytes], facts: MemberFacts | None = None) -> None:
        self.members = members
        self.advanced: list[str] = []
        self.root = facts or MemberFacts(
            root_mode=0o755, root_uid=0, root_gid=0, setid=False, entries=2
        )

    def advance_to(self, member: str) -> None:
        self.advanced.append(member)

    def data(self, member: str, rename_to: str | None = None) -> Iterator[bytes]:
        yield self.members[member]

    def facts(self, member: str) -> MemberFacts:
        return self.root

    def close(self) -> None:
        pass


def run_apply(
    handle: docker_client.DockerHandle,
    instance_id: str,
    plan: p.RestorePlan,
    reader: StaticReader | None = None,
    staged: Any = None,
) -> tuple[list[dict], list[str]]:
    journal: list[dict] = []
    lines: list[str] = []
    env = apply.ApplyEnv(handle, IMAGE, instance_id, 1)

    def open_archive() -> contextlib.AbstractContextManager[Any]:
        assert reader is not None, "this plan has no data"
        return contextlib.nullcontext(reader)

    try:
        apply.apply(
            env,
            plan,
            staged,
            open_archive,
            cancel=threading.Event(),
            log=lines.append,
            journal=journal.append,
        )
    finally:
        lines.append(f"journal: {journal[-1] if journal else None}")
    return journal, lines


@pytest.fixture
def dind() -> Iterator[tuple[docker_client.DockerHandle, Any, str]]:
    """The sshhost daemon over plain TCP and a scratch directory on its host."""
    host = host_docker()
    box = sshhost(host)
    root = f"/srv/drydock-test-{uuid.uuid4().hex[:10]}"
    handle = docker_client.open_client(PLAIN_URL)
    try:
        helper.ensure_image(handle.client, IMAGE)
        sh(box, 'mkdir -p "$1"', root)
        yield handle, box, root
    finally:
        sh(box, 'rm -rf "$1"', root)
        handle.close()
        host.close()


# WIPE


@needs_docker
def test_wipe_helper_has_exactly_dac_override_and_fowner() -> None:
    owner = instance()
    with host_docker() as handle:
        client = handle.client
        try:
            with helper.helper(
                client, IMAGE, owner, ["sleep", "60"], start=True, cap_add=apply.WIPE_CAPS
            ) as box:
                host = client.api.inspect_container(box.id)["HostConfig"]
                caps = sorted(cap.removeprefix("CAP_") for cap in host["CapAdd"])
                assert caps == ["DAC_OVERRIDE", "FOWNER"]
                assert host["CapDrop"] == ["ALL"]
                assert host["ReadonlyRootfs"] is True
                assert "no-new-privileges:true" in host["SecurityOpt"]
                assert host["NetworkMode"] == "none"
            # Every other helper keeps no capabilities at all.
            with helper.helper(client, IMAGE, owner) as box:
                assert not client.api.inspect_container(box.id)["HostConfig"]["CapAdd"]
        finally:
            assert helpers_left(client, owner) == []


@needs_docker
def test_data_helper_has_exactly_chown_fowner_and_fsetid() -> None:
    """Besides the wipe helper, only the data helper that gives the top directory its
    archived owner and mode adds capabilities, and only these three."""
    assert apply.ROOT_CAPS == ["CHOWN", "FOWNER", "FSETID"]
    owner = instance()
    with host_docker() as handle:
        client = handle.client
        try:
            with helper.helper(client, IMAGE, owner, ["true"], cap_add=apply.ROOT_CAPS) as box:
                host = client.api.inspect_container(box.id)["HostConfig"]
                caps = sorted(cap.removeprefix("CAP_") for cap in host["CapAdd"])
                assert caps == ["CHOWN", "FOWNER", "FSETID"]
                assert host["CapDrop"] == ["ALL"] and host["ReadonlyRootfs"] is True
                assert "no-new-privileges:true" in host["SecurityOpt"]
                assert host["NetworkMode"] == "none"
        finally:
            assert helpers_left(client, owner) == []


@needs_docker
def test_wipe_inside_a_sticky_directory_owned_by_another_uid() -> None:
    owner = instance()
    with host_docker() as handle:
        client = handle.client
        helper.ensure_image(client, IMAGE)
        volume = client.volumes.create(
            f"drydock-test-wipe-{uuid.uuid4().hex[:10]}", labels={TEST_LABEL: "1"}
        )
        try:
            client.containers.run(
                IMAGE,
                ["sh", "-c", STICKY_SETUP],
                mounts=[Mount("/v", volume.name, type="volume")],
                labels={TEST_LABEL: "1"},
                network_mode="none",
                remove=True,
            )
            before = stream_probe.describe_volume(client, IMAGE, owner, volume.name)
            assert before["tmp"].mode == 0o1777 and before["tmp"].uid == 1000
            assert before["tmp/other"].uid == 1001 and before["private"].mode == 0o700
            plan = make_plan(wipes=(p.Wipe("volume", volume.name, f"volume {volume.name}"),))
            journal, lines = run_apply(handle, owner, plan)
            assert f"Wiping volume {volume.name}." in lines
            assert journal[-1]["wipe_started"] and journal[-1]["committed"]
            assert set(stream_probe.describe_volume(client, IMAGE, owner, volume.name)) == {""}
        finally:
            volume.remove(force=True)
            assert helpers_left(client, owner) == []


@needs_dind
def test_wipe_refuses_a_target_with_a_mount_inside(dind) -> None:
    """A same-filesystem bind mount below the target has its st_dev, so find -xdev would
    descend into it and delete what it shows."""
    handle, box, root = dind
    owner = instance()
    app, outside = f"{root}/app", f"{root}/outside"
    sh(
        box,
        'mkdir -p "$1/sub" "$2" && printf keep > "$2/f" && printf top > "$1/top"'
        ' && mount --bind "$2" "$1/sub"',
        app,
        outside,
    )
    plan = make_plan(wipes=(p.Wipe("bind", app, f"bind mount {app}"),), write_targets=(app,))
    try:
        with pytest.raises(apply.ApplyError, match="another mount inside it"):
            run_apply(handle, owner, plan)
        assert sh(box, 'cat "$1/f" "$2/top"', outside, app) == "keeptop"
    finally:
        sh(box, 'umount "$1/sub" || true', app)
        assert helpers_left(handle.client, owner) == []


# DATA


@needs_docker
def test_data_gets_the_archived_owner_and_mode_of_its_top_directory() -> None:
    """Docker skips the archive's './' when it extracts into the existing mount point, so a
    fresh volume would stay root:root 0755; the setgid bit needs FSETID."""
    owner = instance()
    member = inner_tar(
        [
            TarEntry("./", tarfile.DIRTYPE, mode=0o2750, uid=999, gid=998),
            TarEntry("./grafana.db", data=b"db", uid=999, gid=998, mode=0o640),
        ]
    )
    facts = MemberFacts(root_mode=0o2750, root_uid=999, root_gid=998, setid=False, entries=2)
    with host_docker() as handle:
        client = handle.client
        helper.ensure_image(client, IMAGE)
        volume = client.volumes.create(
            f"drydock-test-root-{uuid.uuid4().hex[:10]}", labels={TEST_LABEL: "1"}
        )
        step = p.DataStep("volumes/0.tar", "volume", volume.name, f"volume {volume.name}", None)
        try:
            journal, _ = run_apply(
                handle,
                owner,
                make_plan(mode="data-only", data=(step,)),
                StaticReader({"volumes/0.tar": member}, facts),
            )
            assert journal[-1]["committed"] and journal[-1]["volumes"] == [volume.name]
            restored = stream_probe.describe_volume(client, IMAGE, owner, volume.name)
            top = restored[""]
            assert (top.uid, top.gid, top.mode) == (999, 998, 0o2750)
            assert (restored["grafana.db"].uid, restored["grafana.db"].mode) == (999, 0o640)
        finally:
            volume.remove(force=True)
            assert helpers_left(client, owner) == []


@needs_dind
def test_put_archive_preserves_ownership_and_renames_a_file_bind(dind) -> None:
    owner = instance()
    with host_docker() as local:
        client = local.client
        helper.ensure_image(client, IMAGE)
        volume = client.volumes.create(
            f"drydock-test-put-{uuid.uuid4().hex[:10]}", labels={TEST_LABEL: "1"}
        )
        member = inner_tar(
            [
                TarEntry("./", tarfile.DIRTYPE, mode=0o755),
                TarEntry("./data.bin", data=b"owned", uid=999, gid=999, mode=0o600),
                TarEntry("./dir", tarfile.DIRTYPE, mode=0o750, uid=999, gid=999),
            ]
        )
        replace_dir = inner_tar([TarEntry("./dir", data=b"not a directory")])
        try:
            mounts = [Mount(apply.TARGET, volume.name, type="volume")]
            with helper.helper(client, IMAGE, owner, mounts=mounts) as box:
                apply.put_data(client.api, box.id, iter([member]))
                with pytest.raises(docker.errors.APIError):
                    apply.put_data(client.api, box.id, iter([replace_dir]))
            restored = stream_probe.describe_volume(client, IMAGE, owner, volume.name)
            data = restored["data.bin"]
            assert (data.uid, data.gid, data.mode) == (999, 999, 0o600)
            assert restored["dir"].type == tarfile.DIRTYPE and restored["dir"].uid == 999
        finally:
            volume.remove(force=True)
            assert helpers_left(client, owner) == []

    handle, box, root = dind
    sh(box, 'mkdir "$1/conf" && printf old > "$1/conf/keep"', root)
    guard = InnerTarGuard("file", file_name="b0", rename_to="app.conf")
    archived = inner_tar([TarEntry("b0", data=b"listen 80;\n", uid=101, gid=101, mode=0o640)])
    chunks = [guard.feed(archived), guard.close()]
    try:
        mounts = [Mount(apply.TARGET, f"{root}/conf", type="bind")]
        with helper.helper(handle.client, IMAGE, owner, mounts=mounts) as data_box:
            apply.put_data(handle.client.api, data_box.id, iter(chunks))
            assert apply.path_stat(handle.client.api, data_box.id, "/t/app.conf") is not None
        assert sh(box, 'cat "$1/conf/app.conf"', root) == "listen 80;\n"
        assert sh(box, 'stat -c "%u:%g %a" "$1/conf/app.conf"', root).strip() == "101:101 640"
        assert sh(box, 'cat "$1/conf/keep"', root) == "old"
        assert sh(box, 'ls "$1/conf"', root).split() == ["app.conf", "keep"]
    finally:
        assert helpers_left(handle.client, owner) == []


@needs_dind
def test_data_is_not_written_through_a_mount_below_a_bind_directory(dind) -> None:
    """conf below the bind directory is a bind of another directory (/etc, say). The data
    helper mounts the directory without it, so conf/passwd lands in the directory itself."""
    handle, box, root = dind
    owner = instance()
    app, outside = f"{root}/app", f"{root}/outside"
    sh(
        box,
        'mkdir -p "$1/conf" "$2" && printf keep > "$2/passwd" && mount --bind "$2" "$1/conf"',
        app,
        outside,
    )
    member = inner_tar(
        [
            TarEntry("./", tarfile.DIRTYPE, mode=0o755),
            TarEntry("./conf", tarfile.DIRTYPE, mode=0o755),
            TarEntry("./conf/passwd", data=b"planted"),
        ]
    )
    step = p.DataStep("binds/0.tar", "bind-dir", app, f"bind mount {app}", None)
    plan = make_plan(data=(step,), write_targets=(app,))
    try:
        journal, _ = run_apply(handle, owner, plan, StaticReader({"binds/0.tar": member}))
        assert journal[-1]["committed"] and journal[-1]["binds"] == [app]
        assert sh(box, 'cat "$1/passwd"', outside) == "keep"
        sh(box, 'umount "$1/conf"', app)
        assert sh(box, 'cat "$1/conf/passwd"', app) == "planted"
    finally:
        sh(box, 'umount "$1/conf" 2>/dev/null || true', app)
        assert helpers_left(handle.client, owner) == []


# HOST PATHS


@needs_dind
def test_host_path_resolution_follows_symlinks(dind) -> None:
    handle, box, root = dind
    owner = instance()
    sh(
        box,
        'cd "$1" && mkdir -p c/d e && ln -s /etc link && ln -s b a && ln -s c/d b'
        " && ln -s ../c/d e/up && printf f > file",
        root,
    )
    env = apply.ApplyEnv(handle, IMAGE, owner, 1)
    paths = {
        f"{root}/link": "/etc",
        f"{root}/link/passwd": "/etc/passwd",
        f"{root}/missing/x/y": f"{root}/missing/x/y",
        f"{root}/a": f"{root}/c/d",
        f"{root}/a/more": f"{root}/c/d/more",
        f"{root}/e/up": f"{root}/c/d",
        f"{root}/c/d": f"{root}/c/d",
    }
    try:
        assert apply.resolve_paths(env, paths) == paths
        with pytest.raises(HostPathError, match="Drydock never writes to /etc"):
            hostpaths.check_write_target(paths[f"{root}/link"])
        with pytest.raises(apply.ApplyError, match="goes through a file"):
            apply.resolve_paths(env, [f"{root}/file/x"])
    finally:
        assert helpers_left(handle.client, owner) == []


@needs_dind
def test_config_only_plan_with_symlinked_bind_source_is_refused(dind) -> None:
    handle, box, root = dind
    owner = instance()
    sh(box, 'ln -s /etc "$1/l"', root)
    name = f"drydock-test-{uuid.uuid4().hex[:10]}"
    body = {
        "Image": IMAGE,
        "Cmd": ["true"],
        "Labels": {TEST_LABEL: "1"},
        "HostConfig": {"Binds": [f"{root}/l:/conf:ro"]},
    }
    plan = make_plan(
        mode="new-name",
        containers=(p.ContainerStep(name, body, False, None),),
        bind_sources=(f"{root}/l",),
    )
    try:
        with pytest.raises(apply.ApplyError, match="Binding /etc is refused for every role"):
            run_apply(handle, owner, plan)
        assert not handle.client.containers.list(all=True, filters={"name": name})
    finally:
        for container in handle.client.containers.list(all=True, filters={"name": name}):
            container.remove(force=True)
        assert helpers_left(handle.client, owner) == []


@needs_dind
def test_restored_data_cannot_redirect_a_later_mount(dind) -> None:
    """Built by hand: the planner refuses nested write targets outright. The wipe empties
    the outer bind, its data plants sub -> /etc, and the inner bind must not follow it."""
    handle, box, root = dind
    owner = instance()
    marker = f"planted-{uuid.uuid4().hex[:10]}"
    app, sub = f"{root}/app", f"{root}/app/sub"
    sh(box, 'mkdir -p "$1/sub" && printf old > "$1/sub/keep"', app)
    reader = StaticReader(
        {
            "binds/0.tar": inner_tar(
                [
                    TarEntry("./", tarfile.DIRTYPE, mode=0o755),
                    TarEntry("./sub", tarfile.SYMTYPE, linkname="/etc"),
                ]
            ),
            "binds/1.tar": inner_tar(
                [TarEntry("./", tarfile.DIRTYPE, mode=0o755), TarEntry(f"./{marker}", data=b"x")]
            ),
        }
    )
    plan = make_plan(
        wipes=(p.Wipe("bind", app, f"bind mount {app}"),),
        data=(
            p.DataStep("binds/0.tar", "bind-dir", app, f"bind mount {app}", None),
            p.DataStep("binds/1.tar", "bind-dir", sub, f"bind mount {sub}", None),
        ),
        write_targets=(app, sub),
    )
    try:
        with pytest.raises(apply.ApplyError, match=f"{sub} changed during the restore"):
            run_apply(handle, owner, plan, reader)
        assert reader.advanced == ["binds/0.tar", "binds/1.tar"]
        assert sh(box, 'readlink "$1"', sub).strip() == "/etc"
        assert sh(box, 'test ! -e "/etc/$1" && echo absent', marker).strip() == "absent"
    finally:
        assert helpers_left(handle.client, owner) == []


# COMPOSE FILES


@needs_dind
def test_compose_dir_swapped_for_a_link_is_never_written_through(dind, monkeypatch) -> None:
    """Someone who can write to the parent renames the new directory and plants a symbolic
    link to a sibling between the helper's mkdir and its cd (a window widened here by a
    sleep): the sibling keeps its files, and the restore reports a compose problem."""
    handle, box, root = dind
    owner = instance()
    parent = f"{root}/shared"
    sh(
        box,
        'mkdir -p "$1/other" && printf keep > "$1/other/compose.yaml"'
        ' && chown -R 1000:1000 "$1" && chmod 0777 "$1"',
        parent,
    )
    slow = apply.COMPOSE_SCRIPT.replace("|| exit 2; ", "|| exit 2; sleep 5; ", 1)
    assert slow != apply.COMPOSE_SCRIPT
    monkeypatch.setattr(apply, "COMPOSE_SCRIPT", slow)
    data = b"services: {}\n"
    compose = p.ComposeWrite(
        f"{parent}/copy", (p.ComposeOut("compose/0/compose.yaml", "compose.yaml", len(data)),)
    )
    staged = SimpleNamespace(
        manifest=SimpleNamespace(created_at=datetime(2026, 10, 1, tzinfo=UTC)),
        compose={"compose/0/compose.yaml": data},
    )
    swap = threading.Thread(
        target=sh,
        args=(
            box,
            'i=0; until [ -d "$1/copy" ]; do i=$((i + 1)); [ "$i" -lt 600 ] || exit 1;'
            ' sleep 0.1; done; cd "$1" && mv copy moved && ln -s other copy',
            parent,
        ),
    )
    swap.start()
    try:
        journal, _ = run_apply(handle, owner, make_plan(compose=compose), staged=staged)
    finally:
        swap.join(90)
        assert helpers_left(handle.client, owner) == []
    assert sh(box, 'readlink "$1/copy"', parent).strip() == "other"
    assert journal[-1]["committed"] is True
    assert "was moved or replaced while drydock created it" in journal[-1]["compose_problem"]
    assert sh(box, 'cat "$1/other/compose.yaml"; ls -A "$1/moved"', parent) == "keep"
