"""Skipped mounts: the keys a job stores, the choices the form offers, and what capture marks."""

import pytest

from drydock.archive import manifest as m
from drydock.engine import capture
from drydock.hosts.inventory import ContainerInfo, MountInfo, ProjectGroup
from drydock.jobs import mounts


@pytest.mark.parametrize(
    "key",
    ["bind:/opt/imgcache", "bind:/srv/a b/c", "volume:retrak_pgdata", "volume:a.b-c_d"],
)
def test_valid_keys(key: str) -> None:
    assert mounts.key_error(key) is None


@pytest.mark.parametrize(
    "key",
    [
        "bind:relative",
        "bind:/opt/../etc",
        "bind:/opt/x/",
        "bind://host/share",
        "bind:/opt/\x00x",
        "volume:-bad",
        "volume:a/b",
        "tmpfs:/x",
        "/opt/imgcache",
        "bind:/" + "a" * 1100,
    ],
)
def test_invalid_keys(key: str) -> None:
    assert mounts.key_error(key) is not None


def test_check_sorts_dedupes_and_caps() -> None:
    assert mounts.check(["volume:b", "bind:/a", "volume:b"]) == (["bind:/a", "volume:b"], None)
    many = [f"volume:v{n}" for n in range(mounts.MAX_SKIPS + 1)]
    assert mounts.check(many)[1] == f"A job skips at most {mounts.MAX_SKIPS} mounts."


@pytest.mark.parametrize("text", ["", "not json", "{}", '["bind:relative", 3]', None])
def test_a_damaged_stored_value_skips_nothing_invalid(text) -> None:
    assert mounts.stored(text) <= frozenset()


def test_stored_keeps_only_valid_keys() -> None:
    assert mounts.stored('["bind:/opt/c", "bind:rel"]') == frozenset({"bind:/opt/c"})


def container(name: str, *mounts_: MountInfo, cid: str = "c" * 64) -> ContainerInfo:
    return ContainerInfo(cid, name, "img", "running", "Up", None, mounts_, ())


def test_choices_for_a_stack_and_a_container() -> None:
    cache = MountInfo("bind", None, "/opt/imgcache", "/var/cache/nginx", False)
    data = MountInfo("volume", "retrak_pgdata", None, "/var/lib/postgresql", False)
    scratch = MountInfo("tmpfs", None, None, "/scratch", False)
    groups = [
        ProjectGroup(
            "retrak",
            (
                container("retrak-frontend-1", cache, scratch),
                container("retrak-db-1", data, cid="d" * 64),
            ),
        ),
        ProjectGroup(None, (container("other", cache, cid="e" * 64),)),
    ]
    stack = mounts.choices(groups, "stack", "retrak")
    assert [(c.key, c.used_by) for c in stack or []] == [
        ("bind:/opt/imgcache", ("retrak-frontend-1:/var/cache/nginx",)),
        ("volume:retrak_pgdata", ("retrak-db-1:/var/lib/postgresql",)),
    ]
    by_name = mounts.choices(groups, "container", "retrak-db-1")
    assert [c.key for c in by_name or []] == ["volume:retrak_pgdata"]
    by_id = mounts.choices(groups, "container", "d" * 12)
    assert [c.key for c in by_id or []] == ["volume:retrak_pgdata"]
    assert mounts.choices(groups, "stack", "missing") is None
    assert mounts.choices(groups, "container", "d" * 4) is None  # too short to be an ID


def test_capture_marks_what_the_job_skips() -> None:
    ref = m.MountRef(container="c", destination="/d", read_only=False)
    plan = capture.Plan(
        volumes={"keep": {}, "cache": {}},
        binds={"/opt/imgcache": [ref], "/srv/data": [ref], "/etc/app": [ref]},
        refused_binds={"/etc/app": "a system path"},
    )
    capture.skip_mounts(
        plan, frozenset({"bind:/opt/imgcache", "bind:/etc/app", "volume:cache", "volume:gone"})
    )
    assert plan.refused_binds == {
        "/etc/app": "a system path",
        "/opt/imgcache": capture.SKIPPED_BY_JOB,
    }
    assert plan.skipped_volumes == {"cache": capture.SKIPPED_BY_JOB}
    # Skipped binds are read in helpers of their own (skipped_bind_owners), never here.
    assert [x["Source"] for x in capture.data_mounts(plan)] == ["keep", "/srv/data"]


def test_anonymous_volumes_are_marked() -> None:
    anonymous = "babb430a7e945628e1f105c6db0cbe1dcc586753d616d761e66e2211bbcf3515"
    groups = [
        ProjectGroup(
            "app",
            (
                container(
                    "redis",
                    MountInfo("volume", anonymous, None, "/data", False),
                    MountInfo("volume", "app_db", None, "/db", False),
                ),
            ),
        )
    ]
    marks = {c.source: c.anonymous for c in mounts.choices(groups, "stack", "app") or []}
    assert marks == {anonymous: True, "app_db": False}
