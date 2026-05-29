from pathlib import Path


def test_worker_dockerfile_installs_required_runtime_tools_and_scripts():
    text = Path("worker/Dockerfile").read_text()

    assert "FROM ubuntu:" in text
    for package in [
        "gdb",
        "gdb-multiarch",
        "qemu-user",
        "qemu-user-static",
        "file",
        "binutils",
        "patchelf",
        "python3-pip",
        "ripgrep",
        "jq",
        "socat",
        "ncat",
    ]:
        assert package in text
    for python_package in ["pwntools", "ROPGadget", "ropper", "capstone", "unicorn", "z3-solver"]:
        assert python_package in text
    for script in ["binCain-init", "binCain-triage", "binCain-repro", "binCain-primitive"]:
        assert script in text
    assert "/home/kali/workspace" in text
    assert "COPY worker/AGENTS.md /home/kali/AGENTS.md" in text
