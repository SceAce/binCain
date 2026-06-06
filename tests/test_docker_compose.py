from pathlib import Path


def test_docker_compose_defines_interactive_worker_service():
    text = Path("docker-compose.yml").read_text()

    assert "worker:" in text
    assert "dockerfile: worker/Dockerfile" in text
    assert "image: bincain-worker:dev" in text
    assert "./tmp/workspace:/home/kali/workspace" in text
    assert "stdin_open: true" in text
    assert "tty: true" in text


def test_docker_compose_exposes_host_proxy_to_worker():
    text = Path("docker-compose.yml").read_text()

    assert "host.docker.internal:host-gateway" in text
    assert "HTTP_PROXY: http://host.docker.internal:7897" in text
    assert "HTTPS_PROXY: http://host.docker.internal:7897" in text
    assert "ALL_PROXY: socks5://host.docker.internal:7897" in text
    assert "NO_PROXY: localhost,127.0.0.1,::1" in text


def test_gitignore_excludes_compose_workspace():
    text = Path(".gitignore").read_text()

    assert "tmp/" in text
