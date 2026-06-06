from pathlib import Path


def test_worker_dockerfile_installs_expected_pwn_runtime_tools():
    dockerfile = Path("worker/Dockerfile")

    text = dockerfile.read_text()

    assert "FROM ubuntu:" in text
    for package in [
        "gdb",
        "gdb-multiarch",
        "qemu-user",
        "qemu-user-static",
        "patchelf",
        "afl++",
        "radare2",
        "ruby",
        "ruby-dev",
    ]:
        assert package in text
    for python_package in [
        "pwntools",
        "ROPGadget",
        "ropper",
        "angr",
        "z3-solver",
    ]:
        assert python_package in text
    assert "gem install seccomp-tools" in text
    assert "@anthropic-ai/claude-code" in text
    assert "@openai/codex" in text
    assert "binCain-init" in text
    assert "binCain-report" in text
    assert "binCain-repro" in text
    assert "binCain-primitive" in text
    assert "binCain-protocol-template" in text
    assert "/home/kali/workspace" in text
    assert "COPY worker/AGENTS.md /home/kali/workspace/AGENTS.md" in text
    assert "COPY worker/AGENTS.md /home/kali/workspace/CLAUDE.md" in text
    assert "git init" in text
    assert "ENTRYPOINT [\"/entrypoint.sh\"]" in text


def test_worker_entrypoint_preserves_command_argument_boundaries():
    text = Path("worker/entrypoint.sh").read_text()

    assert "runuser -u kali -- \"$@\"" in text
    assert "cmd=\"$*\"" not in text
