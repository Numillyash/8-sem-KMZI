"""Command line interface for KMZI Lab2."""

from __future__ import annotations

import argparse
import json
import shutil
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .broadcast import generate_broadcast_demo, recover_broadcast_message
from .common_modulus import recover_from_known_private_exponent
from .rsa_core import generate_keypair, save_private_key
from .safe_keygen import analyze_rsa_params, generate_safe_rsa_params
from .small_order import generate_small_order_demo, recover_small_order_message
from .wiener import generate_wiener_vulnerable_key, wiener_attack


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _json_ready(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return asdict(value)
    if isinstance(value, tuple):
        return [_json_ready(item) for item in value]
    if isinstance(value, list):
        return [_json_ready(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_ready(item) for key, item in value.items()}
    return value


def _cmd_common_modulus(args: argparse.Namespace) -> int:
    data = _read_json(Path(args.json))
    p, q, d_a = recover_from_known_private_exponent(
        int(data["n"]),
        int(data["e_b"]),
        int(data["d_b"]),
        int(data["e_a"]),
    )
    print(json.dumps({"p": p, "q": q, "d_a": d_a}, indent=2))
    return 0


def _cmd_wiener(args: argparse.Namespace) -> int:
    data = _read_json(Path(args.json))
    result = wiener_attack(int(data["n"]), int(data["e"]))
    print(json.dumps({"found": result is not None, "result": result}, indent=2))
    return 0


def _cmd_broadcast(args: argparse.Namespace) -> int:
    data = _read_json(Path(args.json))
    pairs = [(int(item["n"]), int(item["c"])) for item in data["pairs"]]
    message = recover_broadcast_message(int(data["e"]), pairs)
    print(json.dumps({"message": message}, indent=2))
    return 0


def _cmd_small_order(args: argparse.Namespace) -> int:
    data = _read_json(Path(args.json))
    message, iterations = recover_small_order_message(
        int(data["n"]),
        int(data["e"]),
        int(data["c"]),
    )
    print(json.dumps({"message": message, "iterations": iterations}, indent=2))
    return 0


def _cmd_safe_keygen(args: argparse.Namespace) -> int:
    private = generate_safe_rsa_params(args.bits)
    output = Path(args.out)
    save_private_key(output, private)
    analysis = analyze_rsa_params(private)
    print(json.dumps(_json_ready({"private_key": private, "analysis": analysis}), indent=2))
    return 0


def _build_common_modulus_demo() -> dict[str, Any]:
    private_b, _ = generate_keypair(256, 65537)
    e_a = 17
    phi = (private_b.p - 1) * (private_b.q - 1)
    while True:
        try:
            private_a, _ = generate_keypair_from_existing_primes(private_b.p, private_b.q, e_a)
            break
        except ValueError:
            e_a += 2
    recovered = recover_from_known_private_exponent(private_b.n, private_b.e, private_b.d, e_a)
    return {
        "input": {"n": private_b.n, "e_b": private_b.e, "d_b": private_b.d, "e_a": e_a},
        "expected": {"p": min(private_b.p, private_b.q), "q": max(private_b.p, private_b.q), "d_a": private_a.d},
        "output": {"p": recovered[0], "q": recovered[1], "d_a": recovered[2]},
        "phi": phi,
    }


def generate_keypair_from_existing_primes(p: int, q: int, e: int):
    from .rsa_core import generate_keypair_from_primes

    return generate_keypair_from_primes(p, q, e)


def _cmd_demo(args: argparse.Namespace) -> int:
    output = Path(args.out)
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)

    common = _build_common_modulus_demo()
    _write_json(output / "common_modulus.json", common["input"])

    vulnerable_private, vulnerable_public = generate_wiener_vulnerable_key(256)
    _write_json(
        output / "wiener.json",
        {"n": vulnerable_public.n, "e": vulnerable_public.e, "d_real": vulnerable_private.d},
    )

    broadcast = generate_broadcast_demo(e=3, recipients=3, bits=128)
    _write_json(
        output / "broadcast.json",
        {
            "e": broadcast["e"],
            "message_int": broadcast["message_int"],
            "pairs": [{"n": n, "c": c} for n, c in broadcast["pairs"]],
        },
    )

    small = generate_small_order_demo()
    _write_json(output / "small_order.json", {"n": small["n"], "e": small["e"], "c": small["c"]})

    summary = {
        "common_modulus": common,
        "wiener": {"recovered": wiener_attack(vulnerable_public.n, vulnerable_public.e)},
        "broadcast": _json_ready(broadcast),
        "small_order": small,
    }
    _write_json(output / "demo_outputs.json", summary)
    print(f"Demo data written to {output}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="KMZI Lab2 RSA attacks")
    subparsers = parser.add_subparsers(dest="command", required=True)

    common = subparsers.add_parser("common-modulus")
    common.add_argument("--json", required=True)
    common.set_defaults(func=_cmd_common_modulus)

    wiener = subparsers.add_parser("wiener")
    wiener.add_argument("--json", required=True)
    wiener.set_defaults(func=_cmd_wiener)

    broadcast = subparsers.add_parser("broadcast")
    broadcast.add_argument("--json", required=True)
    broadcast.set_defaults(func=_cmd_broadcast)

    small = subparsers.add_parser("small-order")
    small.add_argument("--json", required=True)
    small.set_defaults(func=_cmd_small_order)

    safe = subparsers.add_parser("safe-keygen")
    safe.add_argument("--bits", type=int, default=1024)
    safe.add_argument("--out", required=True)
    safe.set_defaults(func=_cmd_safe_keygen)

    demo = subparsers.add_parser("demo")
    demo.add_argument("--out", required=True)
    demo.set_defaults(func=_cmd_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
