from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from src.broadcast import generate_broadcast_demo, recover_broadcast_message
from src.common_modulus import recover_from_known_private_exponent
from src.math_utils import gcd, integer_nth_root
from src.rsa_core import generate_keypair, generate_keypair_from_primes
from src.safe_keygen import analyze_rsa_params, generate_safe_rsa_params
from src.small_order import generate_small_order_demo, recover_small_order_message
from src.wiener import generate_wiener_vulnerable_key, wiener_attack


def test_common_modulus_attack_recovers_private_exponent() -> None:
    private_b, _ = generate_keypair(256, 65537)
    phi = (private_b.p - 1) * (private_b.q - 1)
    e_a = 17
    while gcd(e_a, phi) != 1:
        e_a += 2
    private_a, _ = generate_keypair_from_primes(private_b.p, private_b.q, e_a)

    p, q, d_a = recover_from_known_private_exponent(
        private_b.n,
        private_b.e,
        private_b.d,
        e_a,
    )

    assert {p, q} == {private_b.p, private_b.q}
    assert d_a == private_a.d


def test_wiener_attack_recovers_vulnerable_key() -> None:
    private, public = generate_wiener_vulnerable_key(256)
    result = wiener_attack(public.n, public.e)
    assert result is not None
    d, p, q = result
    assert d == private.d
    assert {p, q} == {private.p, private.q}


def test_wiener_attack_returns_none_for_safe_key() -> None:
    private = generate_safe_rsa_params(256)
    assert wiener_attack(private.n, private.e) is None


def test_broadcast_attack_recovers_message() -> None:
    demo = generate_broadcast_demo(e=3, recipients=3, bits=128, message_int=42_4242)
    assert recover_broadcast_message(demo["e"], demo["pairs"]) == demo["message_int"]


def test_broadcast_attack_rejects_bad_inputs() -> None:
    demo = generate_broadcast_demo(e=3, recipients=3, bits=128, message_int=12345)
    pairs = list(demo["pairs"])
    with pytest.raises(ValueError, match="at least e"):
        recover_broadcast_message(3, pairs[:2])
    bad_pairs = [(pairs[0][0], (pairs[0][1] + 1) % pairs[0][0]), pairs[1], pairs[2]]
    with pytest.raises(ValueError, match="exact"):
        recover_broadcast_message(3, bad_pairs)


def test_small_order_attack_recovers_message() -> None:
    demo = generate_small_order_demo()
    recovered, iterations = recover_small_order_message(demo["n"], demo["e"], demo["c"])
    assert recovered == demo["m"]
    assert iterations == demo["iterations"]


def test_safe_keygen_analysis() -> None:
    private = generate_safe_rsa_params(256)
    analysis = analyze_rsa_params(private)
    assert analysis["gcd_e_phi"] == 1
    assert analysis["d_gt_wiener_bound"] is True
    fourth_root, _ = integer_nth_root(private.n, 4)
    assert private.d > fourth_root // 3


def test_cli_demo_smoke(tmp_path: Path) -> None:
    out = tmp_path / "demo"
    result = subprocess.run(
        [sys.executable, "-m", "src.main", "demo", "--out", str(out)],
        cwd=Path(__file__).resolve().parents[1],
        check=True,
        text=True,
        capture_output=True,
    )
    assert "Demo data written" in result.stdout
    assert json.loads((out / "common_modulus.json").read_text(encoding="utf-8"))["n"]
    assert json.loads((out / "demo_outputs.json").read_text(encoding="utf-8"))["small_order"]["recovered_m"]


def test_report_generator_import_and_tmp_output(tmp_path: Path) -> None:
    lab_root = Path(__file__).resolve().parents[1]
    script_path = lab_root / "scripts" / "generate_report_materials.py"
    spec = importlib.util.spec_from_file_location("lab2_generate_report_materials", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    module.generate_report_materials(tmp_path)

    generated = tmp_path / "report" / "generated"
    assert (generated / "report_data.md").exists()
    assert (generated / "report_data.json").exists()
    verification_log = generated / "verification_log.txt"
    assert verification_log.exists()
    log_text = verification_log.read_text(encoding="utf-8")
    assert "common modulus attack OK" in log_text
    assert "Wiener attack OK" in log_text
    assert "broadcast attack OK" in log_text
    assert "small-order attack OK" in log_text
    assert "safe keygen OK" in log_text
    assert "Wiener attack against safe key NOT FOUND" in log_text
