"""提交时签发者未注册（unknown_issuer）的链：事实随链保存，事后注册不得翻转。

覆盖的场景：
- 链提交时签发者未注册 → 以 ``unknown_issuer`` 无效落库；
- 事后注册该主体并轮换到匹配旧签名的密钥（或直接注册匹配密钥）：
  链查询 / 同内容重放 / 只读求值 / 首次核销始终保持原验签拒绝；
- 重启回填不会把提交时未注册的签发者误绑到后来注册的密钥代次，
  原本有效的旧链仍按历史（第 1 代）密钥验签；
- 撤销在这类链上照旧（追加与幂等重放不受影响）。
"""
from __future__ import annotations

import itertools
import json
import sqlite3
from datetime import datetime, timedelta, timezone

from tests.conftest import make_token

_seq = itertools.count(1)


def _now_window(**offsets) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    nb = now + timedelta(seconds=offsets.get("nb", -3600))
    na = now + timedelta(seconds=offsets.get("na", 3600))
    return (
        nb.isoformat().replace("+00:00", "Z"),
        na.isoformat().replace("+00:00", "Z"),
    )


def _ghost_chain(chain_id: str, ghost: str, ghost_secret: str) -> dict:
    """root -> child 两级链；child 由（提交时）未注册主体 ghost 签名。"""
    nb, na = _now_window()
    root = make_token(
        "root", None, "root", ghost,
        "/files/**", ["GET", "POST"],
        not_before=nb, not_after=na, chain_id=chain_id,
    )
    child = make_token(
        "child", "root", ghost, "svc-b",
        "/files/x", ["GET"],
        not_before=nb, not_after=na, chain_id=chain_id,
        secret=ghost_secret,
    )
    return {"chain_id": chain_id, "tokens": [root, child]}


def _submit_ghost_chain(client, ghost_secret: str = "ghost-secret"):
    """提交一条签发者未注册的链，断言以 unknown_issuer 无效落库。"""
    n = next(_seq)
    ghost = f"ghost-{n}"
    chain_id = f"ghost-chain-{n}"
    payload = _ghost_chain(chain_id, ghost, ghost_secret)
    resp = client.post("/api/v1/chains", json=payload)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["integrity"]["allow"] is False
    assert body["integrity"]["first_failed_reason"] == "unknown_issuer"
    return ghost, chain_id, payload, ghost_secret


def _evaluate(client, chain_id: str):
    at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return client.post(
        f"/api/v1/chains/{chain_id}/evaluate",
        json={"request_path": "/files/x", "method": "GET", "at": at},
    )


def _redeem(client, chain_id: str, request_key: str):
    return client.post(
        f"/api/v1/chains/{chain_id}/redeem",
        json={
            "token_id": "child",
            "request_key": request_key,
            "request_path": "/files/x",
            "method": "GET",
        },
    )


def _assert_still_unknown_issuer(client, chain_id: str, payload: dict, request_key: str):
    """查询 / 重放 / 求值 / 首次核销均保持提交时的 unknown_issuer 拒绝。"""
    got = client.get(f"/api/v1/chains/{chain_id}")
    assert got.status_code == 200
    assert got.json()["integrity"]["allow"] is False
    assert got.json()["integrity"]["first_failed_reason"] == "unknown_issuer"

    replay = client.post("/api/v1/chains", json=payload)
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["integrity"]["allow"] is False
    assert replay.json()["integrity"]["first_failed_reason"] == "unknown_issuer"

    evaluated = _evaluate(client, chain_id)
    assert evaluated.status_code == 200
    assert evaluated.json()["decision"] == "deny"
    assert evaluated.json()["first_failed_reason"] == "unknown_issuer"

    redeem = _redeem(client, chain_id, request_key)
    assert redeem.status_code == 200
    assert redeem.json()["redeemed"] is False
    assert redeem.json()["decision"] == "deny"
    assert redeem.json()["first_failed_reason"] == "unknown_issuer"

    # 判定拒绝：不核销、不占用 request_key
    assert client.get(f"/api/v1/chains/{chain_id}").json()["redemptions"] == []


# --------------------------------------------------------------------------- #
# 事后注册（含轮换到匹配旧签名的密钥）不得翻转原验签拒绝
# --------------------------------------------------------------------------- #
def test_registration_and_matching_rotation_do_not_flip_unknown_issuer_chain(client):
    ghost, chain_id, payload, secret = _submit_ghost_chain(client)

    # 事后注册该主体（先装不匹配的密钥），再轮换到匹配旧签名的密钥
    assert client.post(
        "/api/v1/principals", json={"name": ghost, "hmac_secret": "unrelated"}
    ).status_code == 201
    rotated = client.post(
        f"/api/v1/principals/{ghost}/rotate-key", json={"hmac_secret": secret}
    )
    assert rotated.status_code == 200
    assert rotated.json()["generation"] == 2

    _assert_still_unknown_issuer(client, chain_id, payload, f"rk-{chain_id}")

    # 主体本身并未被“污染”：用其当前密钥签出的新链照常通过
    fresh_id = f"{chain_id}-fresh"
    fresh = client.post("/api/v1/chains", json=_ghost_chain(fresh_id, ghost, secret))
    assert fresh.status_code == 201
    assert fresh.json()["integrity"]["allow"] is True


def test_direct_registration_with_matching_secret_does_not_flip(client):
    ghost, chain_id, payload, secret = _submit_ghost_chain(client)

    # 直接以匹配旧签名的密钥注册（第 1 代即匹配）
    assert client.post(
        "/api/v1/principals", json={"name": ghost, "hmac_secret": secret}
    ).status_code == 201

    _assert_still_unknown_issuer(client, chain_id, payload, f"rk-{chain_id}")


def test_restart_backfill_keeps_unknown_issuer_chain_rejected(client):
    from app.database import get_conn, init_db

    ghost, chain_id, payload, secret = _submit_ghost_chain(client)
    assert client.post(
        "/api/v1/principals", json={"name": ghost, "hmac_secret": secret}
    ).status_code == 201

    # 模拟服务重启：回填不得把提交时未注册的签发者绑到后来注册的代次
    with get_conn() as conn:
        init_db(conn)

    _assert_still_unknown_issuer(client, chain_id, payload, f"rk-{chain_id}")


def test_mixed_chain_keeps_registered_issuer_on_locked_generation(client):
    """已注册主体仍按提交时锁定的代次验签；未注册主体的事实随链保存。"""
    n = next(_seq)
    known = f"known-{n}"
    ghost = f"ghost-{n}"
    chain_id = f"mixed-chain-{n}"
    assert client.post(
        "/api/v1/principals", json={"name": known, "hmac_secret": f"{known}-v1"}
    ).status_code == 201

    nb, na = _now_window()
    root = make_token(
        "root", None, "root", known, "/files/**", ["GET"],
        not_before=nb, not_after=na, chain_id=chain_id,
    )
    mid = make_token(
        "mid", "root", known, ghost, "/files/**", ["GET"],
        not_before=nb, not_after=na, chain_id=chain_id, secret=f"{known}-v1",
    )
    child = make_token(
        "child", "mid", ghost, "svc-b", "/files/x", ["GET"],
        not_before=nb, not_after=na, chain_id=chain_id, secret="ghost-secret",
    )
    payload = {"chain_id": chain_id, "tokens": [root, mid, child]}
    resp = client.post("/api/v1/chains", json=payload)
    assert resp.status_code == 201, resp.text
    assert resp.json()["integrity"]["allow"] is False
    assert resp.json()["integrity"]["first_failed_reason"] == "unknown_issuer"

    # 轮换已注册主体到第 2 代；再注册 ghost（密钥恰好匹配旧签名）
    assert client.post(
        f"/api/v1/principals/{known}/rotate-key",
        json={"hmac_secret": f"{known}-v2"},
    ).status_code == 200
    assert client.post(
        "/api/v1/principals", json={"name": ghost, "hmac_secret": "ghost-secret"}
    ).status_code == 201

    evaluated = _evaluate(client, chain_id).json()
    assert evaluated["decision"] == "deny"
    assert evaluated["first_failed_reason"] == "unknown_issuer"
    trace = {node["token_id"]: node for node in evaluated["trace"]}
    # 已注册主体：轮换后仍按提交时锁定的第 1 代密钥验签通过
    mid_sig = next(c for c in trace["mid"]["checks"] if c["name"] == "signature")
    assert mid_sig["passed"] is True
    # 提交时未注册主体：事后注册匹配密钥也不翻转
    child_sig = next(c for c in trace["child"]["checks"] if c["name"] == "signature")
    assert child_sig["passed"] is False
    assert child_sig["reason"] == "unknown_issuer"


def test_revocation_flows_unaffected_on_unknown_issuer_chain(client):
    ghost, chain_id, payload, secret = _submit_ghost_chain(client)
    assert client.post(
        "/api/v1/principals", json={"name": ghost, "hmac_secret": secret}
    ).status_code == 201

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    event = {
        "token_id": "child",
        "effective_at": now,
        "reason": "未知签发者链上的撤销照旧",
        "request_key": f"ops-{chain_id}",
    }
    revoked = client.post(f"/api/v1/chains/{chain_id}/revocations", json=event)
    assert revoked.status_code == 201
    assert revoked.json()["affected_token_ids"] == ["child"]

    # 撤销的同键同内容重放照旧
    replay = client.post(f"/api/v1/chains/{chain_id}/revocations", json=event)
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True

    # 验签拒绝依旧（完整性检查先于撤销解释）
    evaluated = _evaluate(client, chain_id).json()
    assert evaluated["decision"] == "deny"
    assert evaluated["first_failed_reason"] == "unknown_issuer"


# --------------------------------------------------------------------------- #
# 旧库迁移：回填不得把提交时未注册的签发者归到后来注册的代次
# --------------------------------------------------------------------------- #
def _create_pre_fix_db(path: str) -> None:
    """构造修复前版本留下的库（无 chain_unknown_issuers 表）。

    - ``valid-chain``：root -> legacy-a，提交时签发者均已注册，按第 1 代验签通过；
    - ``ghost-chain``：root -> ghost，提交时 ghost 未注册（报告记 unknown_issuer），
      之后 ghost 以匹配旧签名的密钥注册，且旧版回填已把 ghost 误绑到第 1 代。
    """
    from app.engine import validate_chain
    from app.models import CapabilityToken, ChainSubmission

    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE principals (
            name               TEXT PRIMARY KEY,
            hmac_secret        TEXT NOT NULL,
            current_generation INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE chains (
            chain_id       TEXT PRIMARY KEY,
            content_sha256 TEXT NOT NULL,
            report_json    TEXT NOT NULL,
            created_at     TEXT NOT NULL
        );
        CREATE TABLE tokens (
            chain_id    TEXT NOT NULL,
            position    INTEGER NOT NULL,
            token_json  TEXT NOT NULL,
            PRIMARY KEY (chain_id, position)
        );
        CREATE TABLE principal_keys (
            principal    TEXT NOT NULL,
            generation   INTEGER NOT NULL,
            hmac_secret  TEXT NOT NULL,
            created_at   TEXT NOT NULL,
            PRIMARY KEY (principal, generation)
        );
        CREATE TABLE chain_key_generations (
            chain_id   TEXT NOT NULL,
            principal  TEXT NOT NULL,
            generation INTEGER NOT NULL,
            PRIMARY KEY (chain_id, principal)
        );
        """
    )
    now = "2026-01-01T00:00:00+00:00"
    for name, secret in (
        ("root", "test-root-secret"),
        ("legacy-a", "legacy-v1"),
        ("ghost", "ghost-secret"),  # ghost-chain 提交后才注册的主体
    ):
        conn.execute(
            "INSERT INTO principals (name, hmac_secret, current_generation) "
            "VALUES (?, ?, 1)",
            (name, secret),
        )
        conn.execute(
            "INSERT INTO principal_keys "
            "(principal, generation, hmac_secret, created_at) VALUES (?, 1, ?, ?)",
            (name, secret, now),
        )

    # 修复前版本提交时使用的密钥查询：只认识当时已注册的主体
    at_submission = {"root": "test-root-secret", "legacy-a": "legacy-v1"}

    def store(chain_id: str, tokens: list[dict]) -> None:
        submission = ChainSubmission(
            chain_id=chain_id,
            tokens=[CapabilityToken(**t) for t in tokens],
        )
        report, _ = validate_chain(
            submission, lambda name: at_submission.get(name)
        )
        conn.execute(
            "INSERT INTO chains (chain_id, content_sha256, report_json, created_at) "
            "VALUES (?, ?, ?, ?)",
            (
                chain_id,
                "0" * 64,
                json.dumps(report.model_dump(mode="json"), ensure_ascii=False),
                now,
            ),
        )
        for pos, token in enumerate(tokens):
            conn.execute(
                "INSERT INTO tokens (chain_id, position, token_json) VALUES (?, ?, ?)",
                (chain_id, pos, json.dumps(token)),
            )

    store(
        "valid-chain",
        [
            make_token("root", None, "root", "legacy-a", "/files/**", ["GET"],
                       chain_id="valid-chain", secret="test-root-secret"),
            make_token("child", "root", "legacy-a", "svc-b", "/files/x", ["GET"],
                       chain_id="valid-chain", secret="legacy-v1"),
        ],
    )
    conn.execute(
        "INSERT INTO chain_key_generations (chain_id, principal, generation) "
        "VALUES ('valid-chain', 'root', 1), ('valid-chain', 'legacy-a', 1)"
    )

    store(
        "ghost-chain",
        [
            make_token("root", None, "root", "ghost", "/files/**", ["GET"],
                       chain_id="ghost-chain", secret="test-root-secret"),
            make_token("child", "root", "ghost", "svc-b", "/files/x", ["GET"],
                       chain_id="ghost-chain", secret="ghost-secret"),
        ],
    )
    # 旧版回填的误绑：ghost 是事后注册的，却被归到后来注册的第 1 代
    conn.execute(
        "INSERT INTO chain_key_generations (chain_id, principal, generation) "
        "VALUES ('ghost-chain', 'root', 1), ('ghost-chain', 'ghost', 1)"
    )
    conn.commit()
    conn.close()


def test_pre_fix_database_backfill_does_not_bind_late_registered_issuer(tmp_path):
    from app.database import (
        connect,
        init_db,
        install_next_key_generation,
        load_chain_key_generations,
        load_chain_unknown_issuers,
        load_submission,
    )
    from app.engine import validate_chain
    from app.main import _chain_secret_lookup

    db_path = str(tmp_path / "pre-fix.db")
    _create_pre_fix_db(db_path)

    conn = connect(db_path)
    init_db(conn)

    # 提交时未注册的签发者被还原为“未知”，旧版回填的误绑归属被移除
    assert load_chain_unknown_issuers(conn, "ghost-chain") == {"ghost"}
    assert load_chain_key_generations(conn, "ghost-chain") == {"root": 1}

    # 即使当前密钥恰好匹配旧签名，重验仍保持 unknown_issuer 拒绝
    ghost_sub = load_submission(conn, "ghost-chain")
    assert ghost_sub is not None
    report, _ = validate_chain(ghost_sub, _chain_secret_lookup(conn, "ghost-chain"))
    assert report.allow is False
    assert report.first_failed_reason == "unknown_issuer"

    # 原本有效的旧链仍按历史（第 1 代）密钥验签
    assert load_chain_key_generations(conn, "valid-chain") == {
        "root": 1,
        "legacy-a": 1,
    }
    valid_sub = load_submission(conn, "valid-chain")
    assert valid_sub is not None
    report, _ = validate_chain(valid_sub, _chain_secret_lookup(conn, "valid-chain"))
    assert report.allow is True

    # 双方密钥都轮换后：ghost-chain 仍拒绝，valid-chain 仍按第 1 代通过
    install_next_key_generation(conn, "ghost", "ghost-secret-v2")
    install_next_key_generation(conn, "legacy-a", "legacy-v2")
    conn.commit()
    report, _ = validate_chain(ghost_sub, _chain_secret_lookup(conn, "ghost-chain"))
    assert report.allow is False
    assert report.first_failed_reason == "unknown_issuer"
    report, _ = validate_chain(valid_sub, _chain_secret_lookup(conn, "valid-chain"))
    assert report.allow is True

    # 回填幂等：再次“重启”结论不变
    init_db(conn)
    assert load_chain_unknown_issuers(conn, "ghost-chain") == {"ghost"}
    assert load_chain_key_generations(conn, "ghost-chain") == {"root": 1}
    conn.close()
