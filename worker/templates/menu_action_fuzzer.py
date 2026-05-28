#!/usr/bin/env python3
from __future__ import annotations

import os
import random
from dataclasses import dataclass

from pwn import process, remote


@dataclass
class Action:
    name: str
    args: tuple[bytes | int, ...]


def mutate_actions(seed: list[Action], rng: random.Random) -> list[Action]:
    actions = list(seed)
    choice = rng.randrange(4)
    if choice == 0 or not actions:
        actions.append(Action("sendline", (rng.randbytes(rng.randrange(1, 128)),)))
    elif choice == 1:
        index = rng.randrange(len(actions))
        actions[index] = Action("sendline", (rng.randbytes(rng.randrange(1, 256)),))
    elif choice == 2:
        rng.shuffle(actions)
    else:
        actions = actions[: rng.randrange(len(actions) + 1)]
    return actions


def run_case(binary: str, actions: list[Action], *, host: str | None = None, port: int | None = None, timeout: float = 2.0) -> bytes:
    io = remote(host, port, timeout=timeout) if host and port else process([binary])
    transcript = bytearray()
    try:
        for action in actions:
            if action.name == "sendline":
                payload = action.args[0]
                assert isinstance(payload, bytes)
                io.sendline(payload)
            transcript.extend(io.recvrepeat(0.05))
        return bytes(transcript)
    finally:
        io.close()


def main() -> None:
    binary = os.environ.get("BIN", "./chall")
    host = os.environ.get("HOST")
    port = int(os.environ["PORT"]) if os.environ.get("PORT") else None
    rng = random.Random(os.environ.get("SEED", "bincain"))
    seed: list[Action] = []
    for _ in range(int(os.environ.get("CASES", "100"))):
        actions = mutate_actions(seed, rng)
        run_case(binary, actions, host=host, port=port)
        seed = actions


if __name__ == "__main__":
    main()
