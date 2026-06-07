from pathlib import Path


def test_docker_compose_defines_interactive_worker_service():
    text = Path("docker-compose.yml").read_text()

    assert "worker:" in text
    assert "dockerfile: worker/Dockerfile" in text
    assert "image: bincain-worker:dev" in text
    assert "./tmp/workspace:/home/kali/workspace" in text
    assert "stdin_open: true" in text
    assert "tty: true" in text


def test_gitignore_excludes_compose_workspace():
    text = Path(".gitignore").read_text()

    assert "tmp/" in text
