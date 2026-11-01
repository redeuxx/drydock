"""ssh.install_key against a real asyncssh server on 127.0.0.1 that runs commands with sh,
with HOME in a temporary directory, the way a login shell on a remote host would."""

import asyncio
import os
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path

import asyncssh
import pytest

from drydock.hosts import ssh

pytestmark = pytest.mark.anyio

PASSWORD = "correct horse battery staple"
LINE = f"{ssh.AUTHORIZED_KEY_OPTIONS} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTests drydock"


@dataclass
class Server:
    port: int
    home: Path
    host_key: asyncssh.SSHKey
    passwords: list[str] = field(default_factory=list)

    def known_host_line(self, key: asyncssh.SSHKey | None = None) -> str:
        return ssh.known_host_line("127.0.0.1", self.port, key or self.host_key)

    async def install(self, password: str = PASSWORD, line: str = LINE, known: str = "") -> None:
        await ssh.install_key(
            "127.0.0.1", self.port, "admin", known or self.known_host_line(), password, line
        )


@pytest.fixture
async def server(tmp_path: Path) -> AsyncIterator[Server]:
    made = Server(0, tmp_path / "home", asyncssh.generate_private_key("ssh-ed25519"))
    made.home.mkdir()

    class Auth(asyncssh.SSHServer):
        def begin_auth(self, username: str) -> bool:
            return True

        def password_auth_supported(self) -> bool:
            return True

        def validate_password(self, username: str, password: str) -> bool:
            made.passwords.append(password)
            return username == "admin" and password == PASSWORD

    async def run(process: asyncssh.SSHServerProcess) -> None:
        child = await asyncio.create_subprocess_shell(
            process.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={"HOME": str(made.home), "PATH": os.environ["PATH"]},
        )
        _out, err = await child.communicate((await process.stdin.read()).encode())
        process.stderr.write(err.decode())
        process.exit(child.returncode or 0)

    listener = await asyncssh.create_server(
        Auth, "127.0.0.1", 0, server_host_keys=[made.host_key], process_factory=run
    )
    made.port = listener.sockets[0].getsockname()[1]
    try:
        yield made
    finally:
        listener.close()
        await listener.wait_closed()


async def test_installs_the_line_once_with_private_modes(server: Server) -> None:
    await server.install()
    await server.install()
    keys = server.home / ".ssh" / "authorized_keys"
    assert keys.read_text() == LINE + "\n"
    assert (server.home / ".ssh").stat().st_mode & 0o777 == 0o700
    assert keys.stat().st_mode & 0o777 == 0o600


async def test_appends_after_a_line_without_a_final_newline(server: Server) -> None:
    (server.home / ".ssh").mkdir(mode=0o700)
    keys = server.home / ".ssh" / "authorized_keys"
    keys.write_text("ssh-ed25519 AAAAexisting user@laptop")
    await server.install()
    assert keys.read_text() == "ssh-ed25519 AAAAexisting user@laptop\n" + LINE + "\n"


async def test_a_wrong_password_is_refused(server: Server) -> None:
    with pytest.raises(ssh.SSHKeyError, match="refused the password for admin") as caught:
        await server.install(password="wrong password 7c1e")
    assert "wrong password 7c1e" not in str(caught.value)
    assert not (server.home / ".ssh").exists()


async def test_a_different_host_key_never_gets_the_password(server: Server) -> None:
    impostor = asyncssh.generate_private_key("ssh-ed25519")
    with pytest.raises(ssh.SSHKeyError, match="No password was sent"):
        await server.install(known=server.known_host_line(impostor))
    assert server.passwords == []


async def test_a_failing_install_says_so_without_the_password(server: Server) -> None:
    (server.home / ".ssh").write_text("a file where the directory should be")
    with pytest.raises(ssh.SSHKeyError, match="could not add the key") as caught:
        await server.install()
    assert PASSWORD not in str(caught.value)


async def test_the_line_is_data_not_a_command(server: Server) -> None:
    hostile = LINE + ' "; touch $HOME/pwned; echo "'
    await server.install(line=hostile)
    assert not (server.home / "pwned").exists()
    assert (server.home / ".ssh" / "authorized_keys").read_text() == hostile + "\n"
