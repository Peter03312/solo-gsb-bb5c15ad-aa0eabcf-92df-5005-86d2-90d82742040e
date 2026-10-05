"""到期清除正文（scheduled purge）功能测试。

规则要点（规格）：
- 封存人凭现有密钥提交带时区的未来清除时刻（PUT /documents/{id}/purge），
  到期前可改期（再次 PUT）或取消（DELETE）；
- 交接后清除安排保留，由新封存人管理，原封存人无权操作（403）；
- 到期时无论扫描器是否准时运行，后续查询与操作都呈现已清除结果：
  正文从库中清空，状态 purged，保留摘要、参与方与审计元数据，
  任何接口不再返回正文；
- 已开封资料仍按期清除；未开封资料的进行中开封请求失效（旧同意作废）、
  待确认交接邀请失效；
- 清除与最早开封同刻时清除优先；开封更早则先开封再清除；
- 并发交接确认、见证同意与清除只产生一个一致结果；
- 已清除资料不能再开封、替换见证人、交接或再安排清除；
- 无权、无效时刻、已到期的改期或取消一律拒绝且不泄露正文。
"""
import contextlib
import datetime as dt
import os
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from conftest import auth, digest_of, register, seal

BODY = "到期清除绝密资料 PURGE-SECRET"


def _in_seconds(s: float) -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=s)).isoformat()


def _in_hours(h: float) -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=h)).isoformat()


def _setup(client, names=("owner", "w1", "w2", "w3", "new", "other")):
    keys = {n: register(client, n) for n in names}
    d = seal(client, keys["owner"], BODY, ["w1", "w2", "w3"])
    return keys, d["document_id"], d["digest"]


def _put_purge(client, key, doc_id, purge_at):
    return client.put(
        f"/documents/{doc_id}/purge", json={"purge_at": purge_at}, headers=auth(key)
    )


def _del_purge(client, key, doc_id):
    return client.delete(f"/documents/{doc_id}/purge", headers=auth(key))


def _create_request(client, owner_key, doc_id, *, deadline_h=2, earliest_s=None):
    payload = {"reason": "清除测试", "deadline": _in_hours(deadline_h)}
    if earliest_s is not None:
        payload["earliest_open_at"] = _in_seconds(earliest_s)
    r = client.post(f"/documents/{doc_id}/open-requests", json=payload, headers=auth(owner_key))
    assert r.status_code == 201, r.text
    return r.json()


def _approve(client, key, req, dg):
    return client.post(f"/open-requests/{req}/approve", json={"digest": dg}, headers=auth(key))


def _get(client, key, doc_id):
    return client.get(f"/documents/{doc_id}", headers=auth(key))


def _audit(client, key, doc_id):
    return client.get(f"/documents/{doc_id}/audit", headers=auth(key)).json()["records"]


@pytest.fixture
def passive_client(tmp_path, monkeypatch):
    """后台扫描间隔拉到 1 小时：验证写事务/查询临界区自行做到点清除判定。"""
    monkeypatch.setenv("SEAL_DB_PATH", str(tmp_path / "passive-purge.db"))
    monkeypatch.setenv("SWEEP_INTERVAL_SECONDS", "3600")
    from app.main import app

    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# 安排清除：创建、响应与元数据展示
# ---------------------------------------------------------------------------


def test_schedule_purge_success_and_metadata(client):
    keys, doc_id, dg = _setup(client)
    purge_at = _in_hours(1)
    r = _put_purge(client, keys["owner"], doc_id, purge_at)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["document_id"] == doc_id
    assert data["status"] == "sealed"
    assert data["purge_at"].endswith("+00:00")
    assert data["previous_purge_at"] is None
    assert BODY not in r.text

    # 详情与列表都展示清除时刻；正文仍不可见
    got = _get(client, keys["owner"], doc_id).json()
    assert got["status"] == "sealed" and got["purge_at"] == data["purge_at"]
    assert "body" not in got and "purged_at" not in got
    listed = client.get("/documents", headers=auth(keys["owner"])).json()["documents"]
    assert listed[0]["purge_at"] == data["purge_at"] and listed[0]["status"] == "sealed"
    # 见证人也可见清除时刻（仅元数据）
    got_w = _get(client, keys["w1"], doc_id).json()
    assert got_w["purge_at"] == data["purge_at"] and "body" not in got_w

    actions = [r["action"] for r in _audit(client, keys["owner"], doc_id)]
    assert actions == ["seal", "purge_scheduled"]


def test_schedule_purge_validation(client):
    keys, doc_id, _ = _setup(client)
    future = _in_hours(1)

    # 无密钥 / 错密钥 -> 401
    assert client.put(f"/documents/{doc_id}/purge", json={"purge_at": future}).status_code == 401
    assert _put_purge(client, "deadbeef", doc_id, future).status_code == 401
    # 见证人 / 无关账号 -> 403（不区分资料是否存在）
    assert _put_purge(client, keys["w1"], doc_id, future).status_code == 403
    assert _put_purge(client, keys["other"], doc_id, future).status_code == 403
    assert _put_purge(client, keys["other"], 9999, future).status_code == 403
    # 清除时刻已过 -> 400
    assert _put_purge(client, keys["owner"], doc_id, "2020-01-01T00:00:00Z").status_code == 400
    # 不带时区 -> 422，不回显内容
    r = _put_purge(client, keys["owner"], doc_id, "2030-01-01T00:00:00")
    assert r.status_code == 422 and BODY not in r.text
    # 缺字段 -> 422
    assert client.put(f"/documents/{doc_id}/purge", json={}, headers=auth(keys["owner"])).status_code == 422
    # 取消同样需要封存人身份
    assert client.delete(f"/documents/{doc_id}/purge").status_code == 401
    assert _del_purge(client, keys["w1"], doc_id).status_code == 403

    # 全部拒绝均不产生安排：随后可正常安排
    assert _put_purge(client, keys["owner"], doc_id, future).status_code == 200
    assert [r["action"] for r in _audit(client, keys["owner"], doc_id)] == ["seal", "purge_scheduled"]


def test_reschedule_and_cancel(client):
    keys, doc_id, _ = _setup(client)
    t1 = _in_hours(1)
    assert _put_purge(client, keys["owner"], doc_id, t1).status_code == 200

    # 改期
    t2 = _in_hours(2)
    r = _put_purge(client, keys["owner"], doc_id, t2)
    assert r.status_code == 200
    assert r.json()["purge_at"] != r.json()["previous_purge_at"]
    assert r.json()["previous_purge_at"] is not None
    got = _get(client, keys["owner"], doc_id).json()
    assert got["purge_at"] == r.json()["purge_at"]

    # 取消
    r = _del_purge(client, keys["owner"], doc_id)
    assert r.status_code == 200 and r.json()["purge_at"] is None
    assert _get(client, keys["owner"], doc_id).json()["purge_at"] is None

    # 重复取消 -> 409；取消后可重新安排
    assert _del_purge(client, keys["owner"], doc_id).status_code == 409
    assert _put_purge(client, keys["owner"], doc_id, _in_hours(3)).status_code == 200

    actions = [r["action"] for r in _audit(client, keys["owner"], doc_id)]
    assert actions == ["seal", "purge_scheduled", "purge_rescheduled",
                       "purge_canceled", "purge_scheduled"]


# ---------------------------------------------------------------------------
# 到期清除：扫描器执行与读路径确定性执行
# ---------------------------------------------------------------------------


def test_purge_executes_at_due_time(client, sweep):
    keys, doc_id, dg = _setup(client)
    r = _put_purge(client, keys["owner"], doc_id, _in_seconds(1))
    purge_at = r.json()["purge_at"]
    time.sleep(1.15)
    sweep()

    got = _get(client, keys["owner"], doc_id)
    assert BODY not in got.text
    data = got.json()
    assert data["status"] == "purged"
    assert data["purge_at"] == purge_at
    assert data["purged_at"] == purge_at      # 清除时刻 = 约定时刻
    assert data["digest"] == dg               # 摘要保留
    assert data["witnesses"] == ["w1", "w2", "w3"]  # 参与方保留
    assert "body" not in data                 # 任何接口不再返回正文

    listed = client.get("/documents", headers=auth(keys["owner"])).json()["documents"]
    assert listed[0]["status"] == "purged" and listed[0]["purged_at"] == purge_at
    assert BODY not in client.get("/documents", headers=auth(keys["owner"])).text

    actions = [r["action"] for r in _audit(client, keys["owner"], doc_id)]
    assert actions == ["seal", "purge_scheduled", "purged"]


def test_purge_executed_by_read_without_sweeper(passive_client):
    """无后台扫描时，查询本身确定性呈现已清除结果。"""
    client = passive_client
    keys, doc_id, _ = _setup(client)
    _put_purge(client, keys["owner"], doc_id, _in_seconds(1))
    time.sleep(1.15)

    got = _get(client, keys["owner"], doc_id)
    assert got.json()["status"] == "purged" and BODY not in got.text
    # 列表查询同样呈现已清除
    listed = client.get("/documents", headers=auth(keys["owner"])).json()["documents"]
    assert listed[0]["status"] == "purged"
    # 审计查询包含 purged 记录
    assert "purged" in [r["action"] for r in _audit(client, keys["owner"], doc_id)]


def test_purged_body_never_returned_and_db_cleared(client, sweep):
    """清除后任何接口（含审计、错误体）都不含正文；库中正文已清空。"""
    keys, doc_id, _ = _setup(client)
    _put_purge(client, keys["owner"], doc_id, _in_seconds(1))
    time.sleep(1.15)
    sweep()

    for resp in [
        _get(client, keys["owner"], doc_id),
        client.get("/documents", headers=auth(keys["owner"])),
        client.get(f"/documents/{doc_id}/audit", headers=auth(keys["owner"])),
        _get(client, keys["w1"], doc_id),
        client.post(f"/documents/{doc_id}/open-requests",
                    json={"reason": "x", "deadline": _in_hours(1)}, headers=auth(keys["owner"])),
    ]:
        assert BODY not in resp.text

    conn = sqlite3.connect(os.environ["SEAL_DB_PATH"])
    row = conn.execute("SELECT body, status, digest FROM documents WHERE id=?", (doc_id,)).fetchone()
    assert row[0] == "" and row[1] == "purged" and row[2] == digest_of(BODY)
    conn.close()


# ---------------------------------------------------------------------------
# 清除的连带结算：进行中请求、旧同意、待确认邀请
# ---------------------------------------------------------------------------


def test_purge_invalidates_active_request_approvals_and_invitation(client, sweep):
    keys, doc_id, dg = _setup(client)
    req = _create_request(client, keys["owner"], doc_id)["request_id"]
    assert _approve(client, keys["w1"], req, dg).json()["approval_count"] == 1
    inv = client.post(
        f"/documents/{doc_id}/handover-invitations",
        json={"to_username": "new", "confirm_deadline": _in_hours(1)},
        headers=auth(keys["owner"]),
    ).json()["invitation_id"]

    _put_purge(client, keys["owner"], doc_id, _in_seconds(1))
    time.sleep(1.15)
    sweep()

    got = _get(client, keys["owner"], doc_id).json()
    assert got["status"] == "purged"
    # 进行中请求失效、旧同意作废
    assert got["open_request"]["status"] == "invalidated"
    assert got["witness_approvals"] == []
    # 待确认邀请失效
    inv_view = client.get(f"/handover-invitations/{inv}", headers=auth(keys["owner"])).json()
    assert inv_view["status"] == "expired"
    # 旧请求不能再同意；邀请不能再确认
    assert _approve(client, keys["w2"], req, dg).status_code == 409
    assert client.post(f"/handover-invitations/{inv}/confirm", headers=auth(keys["new"])).status_code == 409

    actions = [r["action"] for r in _audit(client, keys["owner"], doc_id)]
    assert actions.index("request_invalidated") < actions.index("purged")
    assert "handover_invitation_expired" in actions


def test_purge_opened_document_on_schedule(client, sweep):
    """已开封资料仍按期清除：正文不再返回，摘要/开封时刻/见证记录保留。"""
    keys, doc_id, dg = _setup(client)
    req = _create_request(client, keys["owner"], doc_id)["request_id"]
    _approve(client, keys["w1"], req, dg)
    assert _approve(client, keys["w2"], req, dg).json()["status"] == "opened"
    assert _get(client, keys["owner"], doc_id).json()["body"] == BODY

    _put_purge(client, keys["owner"], doc_id, _in_seconds(1))
    time.sleep(1.15)
    sweep()

    got = _get(client, keys["owner"], doc_id)
    assert BODY not in got.text
    data = got.json()
    assert data["status"] == "purged" and "body" not in data
    assert data["digest"] == dg
    assert data["opened_at"] is not None
    assert data["purged_at"] == data["purge_at"]
    # 见证记录（参与方元数据）保留
    assert [a["username"] for a in data["witness_approvals"]] == ["w1", "w2"]
    actions = [r["action"] for r in _audit(client, keys["owner"], doc_id)]
    assert actions.index("opened") < actions.index("purged")


# ---------------------------------------------------------------------------
# 清除与最早开封的时序规则
# ---------------------------------------------------------------------------


def test_purge_wins_over_same_time_open(passive_client):
    """清除与最早开封同刻：清除优先，不开封，waiting 请求失效。"""
    client = passive_client
    keys, doc_id, dg = _setup(client)
    req = _create_request(client, keys["owner"], doc_id, deadline_h=2, earliest_s=1)
    req_id = req["request_id"]
    _approve(client, keys["w1"], req_id, dg)
    assert _approve(client, keys["w2"], req_id, dg).json()["status"] == "waiting"
    # 清除时刻 = 最早开封时刻（同一时刻）
    assert _put_purge(client, keys["owner"], doc_id, req["earliest_open_at"]).status_code == 200

    time.sleep(1.2)
    got = _get(client, keys["owner"], doc_id).json()
    assert got["status"] == "purged" and "body" not in got
    assert got["open_request"]["status"] == "invalidated"
    actions = [r["action"] for r in _audit(client, keys["owner"], doc_id)]
    assert "opened" not in actions
    assert actions.index("request_invalidated") < actions.index("purged")


def test_open_earlier_than_purge_opens_first(client):
    """开封时刻更早：到点先开封，到清除时刻再清除正文。"""
    keys, doc_id, dg = _setup(client)
    req = _create_request(client, keys["owner"], doc_id, deadline_h=2, earliest_s=1)
    req_id = req["request_id"]
    _approve(client, keys["w1"], req_id, dg)
    assert _approve(client, keys["w2"], req_id, dg).json()["status"] == "waiting"
    _put_purge(client, keys["owner"], doc_id, _in_seconds(2.5))

    # 到最早开封时刻（清除时刻未到）：后台扫描器先开封
    deadline = time.time() + 5
    opened = False
    while time.time() < deadline:
        got = _get(client, keys["owner"], doc_id).json()
        if got["status"] == "opened":
            opened = True
            break
        time.sleep(0.1)
    assert opened and got["body"] == BODY

    # 到清除时刻：正文被清除
    deadline = time.time() + 8
    purged = False
    while time.time() < deadline:
        got = _get(client, keys["owner"], doc_id).json()
        if got["status"] == "purged":
            purged = True
            break
        time.sleep(0.1)
    assert purged and "body" not in got
    actions = [r["action"] for r in _audit(client, keys["owner"], doc_id)]
    assert actions.index("opened") < actions.index("purged")


def test_open_earlier_than_purge_late_processing(passive_client):
    """扫描器/事务都延迟到两个时刻之后：仍先补开封、再清除，历史一致。"""
    client = passive_client
    keys, doc_id, dg = _setup(client)
    req = _create_request(client, keys["owner"], doc_id, deadline_h=2, earliest_s=1)
    req_id = req["request_id"]
    _approve(client, keys["w1"], req_id, dg)
    _approve(client, keys["w2"], req_id, dg)
    _put_purge(client, keys["owner"], doc_id, _in_seconds(2))

    time.sleep(2.3)  # 两个时刻都已过，期间无任何扫描/写事务
    got = _get(client, keys["owner"], doc_id).json()
    assert got["status"] == "purged"
    assert got["opened_at"] is not None  # 先开过后清除
    actions = [r["action"] for r in _audit(client, keys["owner"], doc_id)]
    assert actions.index("opened") < actions.index("purged")


def test_purge_earlier_than_earliest_open_prevents_open(passive_client):
    """清除时刻早于最早开封时刻：资料直接清除，永远不会开封。"""
    client = passive_client
    keys, doc_id, dg = _setup(client)
    req = _create_request(client, keys["owner"], doc_id, deadline_h=2, earliest_s=2)
    req_id = req["request_id"]
    _approve(client, keys["w1"], req_id, dg)
    _approve(client, keys["w2"], req_id, dg)
    _put_purge(client, keys["owner"], doc_id, _in_seconds(1))

    time.sleep(2.3)  # 两个时刻都已过
    got = _get(client, keys["owner"], doc_id).json()
    assert got["status"] == "purged"
    actions = [r["action"] for r in _audit(client, keys["owner"], doc_id)]
    assert "opened" not in actions


# ---------------------------------------------------------------------------
# 已清除资料的拒绝路径
# ---------------------------------------------------------------------------


def test_purged_document_rejects_all_operations(client, sweep):
    keys, doc_id, dg = _setup(client)
    req = _create_request(client, keys["owner"], doc_id)["request_id"]
    _put_purge(client, keys["owner"], doc_id, _in_seconds(1))
    time.sleep(1.15)
    sweep()
    assert _get(client, keys["owner"], doc_id).json()["status"] == "purged"

    future = _in_hours(1)
    # 不能再开封 / 同意 / 撤销
    assert client.post(f"/documents/{doc_id}/open-requests",
                       json={"reason": "x", "deadline": future},
                       headers=auth(keys["owner"])).status_code == 409
    assert _approve(client, keys["w1"], req, dg).status_code == 409
    assert client.post(f"/open-requests/{req}/revoke", json={},
                       headers=auth(keys["owner"])).status_code == 409
    # 不能替换见证人
    assert client.post(f"/documents/{doc_id}/witness-replacements",
                       json={"old_witness": "w3", "new_witness": "new"},
                       headers=auth(keys["owner"])).status_code == 409
    # 不能发起交接
    assert client.post(f"/documents/{doc_id}/handover-invitations",
                       json={"to_username": "new", "confirm_deadline": future},
                       headers=auth(keys["owner"])).status_code == 409
    # 不能再安排/改期/取消清除
    assert _put_purge(client, keys["owner"], doc_id, future).status_code == 409
    assert _del_purge(client, keys["owner"], doc_id).status_code == 409

    # 查询与审计仍可用（仅元数据）
    assert _get(client, keys["owner"], doc_id).status_code == 200
    assert client.get(f"/documents/{doc_id}/audit", headers=auth(keys["owner"])).status_code == 200
    # 拒绝路径均未产生新审计
    actions = [r["action"] for r in _audit(client, keys["owner"], doc_id)]
    assert actions.count("purged") == 1
    assert "purge_rescheduled" not in actions and "purge_canceled" not in actions


def test_due_schedule_rejects_reschedule_and_cancel(passive_client):
    """清除时刻已到（扫描器未运行）：改期与取消都被拒，且清除先生效。"""
    client = passive_client
    keys, doc_id, _ = _setup(client)
    _put_purge(client, keys["owner"], doc_id, _in_seconds(1))
    time.sleep(1.15)

    r = _put_purge(client, keys["owner"], doc_id, _in_hours(1))
    assert r.status_code == 409 and BODY not in r.text
    assert _get(client, keys["owner"], doc_id).json()["status"] == "purged"

    r = _del_purge(client, keys["owner"], doc_id)
    assert r.status_code == 409 and BODY not in r.text
    actions = [r["action"] for r in _audit(client, keys["owner"], doc_id)]
    assert actions.count("purged") == 1


def test_due_purge_commits_with_rejected_write(passive_client):
    """清除时刻已到：写操作（提交开封请求）被拒 409，且清除随该请求一并落库。"""
    client = passive_client
    keys, doc_id, _ = _setup(client)
    _put_purge(client, keys["owner"], doc_id, _in_seconds(1))
    time.sleep(1.15)

    r = client.post(
        f"/documents/{doc_id}/open-requests",
        json={"reason": "迟到的新请求", "deadline": _in_hours(1)},
        headers=auth(keys["owner"]),
    )
    assert r.status_code == 409 and BODY not in r.text
    # 清除已随本次写事务提交：直接冷读库即为 purged、正文已清空
    conn = sqlite3.connect(os.environ["SEAL_DB_PATH"])
    row = conn.execute("SELECT status, body FROM documents WHERE id=?", (doc_id,)).fetchone()
    assert row[0] == "purged" and row[1] == ""
    conn.close()


# ---------------------------------------------------------------------------
# 交接后清除管理权转移
# ---------------------------------------------------------------------------


def test_handover_transfers_purge_management(client):
    keys, doc_id, _ = _setup(client)
    _put_purge(client, keys["owner"], doc_id, _in_hours(1))
    inv = client.post(
        f"/documents/{doc_id}/handover-invitations",
        json={"to_username": "new", "confirm_deadline": _in_hours(1)},
        headers=auth(keys["owner"]),
    ).json()["invitation_id"]
    r = client.post(f"/handover-invitations/{inv}/confirm", headers=auth(keys["new"]))
    assert r.status_code == 200, r.text

    # 清除安排随资料保留；原封存人无权改期/取消
    assert _get(client, keys["new"], doc_id).json()["purge_at"] is not None
    assert _put_purge(client, keys["owner"], doc_id, _in_hours(2)).status_code == 403
    assert _del_purge(client, keys["owner"], doc_id).status_code == 403
    # 新封存人可改期与取消
    assert _put_purge(client, keys["new"], doc_id, _in_hours(2)).status_code == 200
    assert _del_purge(client, keys["new"], doc_id).status_code == 200
    assert _get(client, keys["new"], doc_id).json()["purge_at"] is None


# ---------------------------------------------------------------------------
# 冷读库一致性
# ---------------------------------------------------------------------------


def test_purge_persists_cold_read(client, sweep):
    keys, doc_id, dg = _setup(client)
    req = _create_request(client, keys["owner"], doc_id)["request_id"]
    _approve(client, keys["w1"], req, dg)
    r = _put_purge(client, keys["owner"], doc_id, _in_seconds(1))
    purge_at = r.json()["purge_at"]
    time.sleep(1.15)
    sweep()

    conn = sqlite3.connect(os.environ["SEAL_DB_PATH"])
    row = conn.execute(
        "SELECT status, body, digest, purge_at, purged_at FROM documents WHERE id=?",
        (doc_id,),
    ).fetchone()
    assert row[0] == "purged" and row[1] == ""
    assert row[2] == dg and row[3] == purge_at and row[4] == purge_at
    assert conn.execute(
        "SELECT status FROM open_requests WHERE id=?", (req,)
    ).fetchone()[0] == "invalidated"
    assert conn.execute(
        "SELECT COUNT(*) FROM approvals WHERE request_id=?", (req,)
    ).fetchone()[0] == 0
    # 见证人与封存人关系保留
    assert conn.execute(
        "SELECT COUNT(*) FROM document_witnesses WHERE document_id=?", (doc_id,)
    ).fetchone()[0] == 3
    conn.close()


# ---------------------------------------------------------------------------
# 重启恢复：停机期间到点的清除在启动时生效
# ---------------------------------------------------------------------------


def _start_server(tmp_path, monkeypatch, db_name, sweep_seconds):
    import socket
    import threading

    import httpx
    import uvicorn

    from app.main import app

    monkeypatch.setenv("SEAL_DB_PATH", str(tmp_path / db_name))
    monkeypatch.setenv("SWEEP_INTERVAL_SECONDS", str(sweep_seconds))
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    end = time.time() + 10
    while time.time() < end:
        try:
            if httpx.get(base + "/health", timeout=1).status_code == 200:
                break
        except Exception:
            time.sleep(0.1)
    else:
        raise AssertionError("server did not start")
    return server, thread, base


def test_purge_recovered_after_restart(tmp_path, monkeypatch):
    """服务停机期间到达清除时刻：重启时的恢复扫描必须完成清除。"""
    import httpx

    server, thread, base = _start_server(tmp_path, monkeypatch, "restart-purge.db", 3600)
    try:
        with httpx.Client(timeout=10) as c:
            def reg(n):
                return c.post(base + "/register", json={"username": n}).json()["api_key"]

            owner = reg("rp-owner")
            for n in ("rp-w1", "rp-w2", "rp-w3"):
                reg(n)
            doc_id = c.post(
                base + "/documents",
                json={"body": "RESTART-PURGE-SECRET", "witnesses": ["rp-w1", "rp-w2", "rp-w3"]},
                headers={"X-API-Key": owner},
            ).json()["document_id"]
            purge_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=1)).isoformat()
            r = c.put(f"{base}/documents/{doc_id}/purge",
                      json={"purge_at": purge_at}, headers={"X-API-Key": owner})
            assert r.status_code == 200
    finally:
        server.should_exit = True
        thread.join(timeout=5)

    time.sleep(1.2)  # 清除时刻在“停机”期间流逝

    server2, thread2, base2 = _start_server(tmp_path, monkeypatch, "restart-purge.db", 3600)
    try:
        with httpx.Client(timeout=10) as c:
            got = c.get(f"{base2}/documents/{doc_id}", headers={"X-API-Key": owner})
            assert got.status_code == 200
            data = got.json()
            assert data["status"] == "purged" and "body" not in data
            assert "RESTART-PURGE-SECRET" not in got.text
            records = c.get(f"{base2}/documents/{doc_id}/audit",
                            headers={"X-API-Key": owner}).json()["records"]
            assert [r["action"] for r in records].count("purged") == 1
    finally:
        server2.should_exit = True
        thread2.join(timeout=5)


# ---------------------------------------------------------------------------
# 并发：清除到点后，交接确认与见证同意赛跑 —— 唯一一致结果
# ---------------------------------------------------------------------------


def test_concurrent_confirm_and_approve_with_due_purge(tmp_path, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    import httpx

    server, thread, base = _start_server(tmp_path, monkeypatch, "purge-race.db", 60)
    try:
        with httpx.Client(timeout=10) as c:
            def reg(n):
                return c.post(base + "/register", json={"username": n}).json()["api_key"]

            owner, new = reg("pr-owner"), reg("pr-new")
            w1, w2, w3 = reg("pr-w1"), reg("pr-w2"), reg("pr-w3")
            body = "PURGE-RACE-SECRET"
            dg = digest_of(body)
            doc_id = c.post(
                base + "/documents",
                json={"body": body, "witnesses": ["pr-w1", "pr-w2", "pr-w3"]},
                headers={"X-API-Key": owner},
            ).json()["document_id"]
            deadline = _in_hours(1)
            req_id = c.post(
                f"{base}/documents/{doc_id}/open-requests",
                json={"reason": "赛跑", "deadline": deadline},
                headers={"X-API-Key": owner},
            ).json()["request_id"]
            assert c.post(f"{base}/open-requests/{req_id}/approve",
                          json={"digest": dg}, headers={"X-API-Key": w1}).status_code == 200
            inv_id = c.post(
                f"{base}/documents/{doc_id}/handover-invitations",
                json={"to_username": "pr-new", "confirm_deadline": deadline},
                headers={"X-API-Key": owner},
            ).json()["invitation_id"]
            purge_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=1.2)).isoformat()
            assert c.put(f"{base}/documents/{doc_id}/purge",
                         json={"purge_at": purge_at},
                         headers={"X-API-Key": owner}).status_code == 200

        time.sleep(1.4)  # 清除时刻已过，扫描器不运行（60s 间隔）
        barrier = threading.Barrier(2)

        def do_confirm():
            barrier.wait()
            with httpx.Client(timeout=10) as c:
                return c.post(f"{base}/handover-invitations/{inv_id}/confirm",
                              headers={"X-API-Key": new}).status_code

        def do_approve():
            barrier.wait()
            with httpx.Client(timeout=10) as c:
                return c.post(f"{base}/open-requests/{req_id}/approve",
                              json={"digest": dg}, headers={"X-API-Key": w2}).status_code

        with ThreadPoolExecutor(max_workers=2) as pool:
            cf_code, ap_code = list(pool.map(lambda f: f(), [do_confirm, do_approve]))

        # 清除到点后：确认与同意都只能被拒，资料呈现唯一已清除终态
        assert cf_code == 409 and ap_code == 409
        with httpx.Client(timeout=10) as c:
            got = c.get(f"{base}/documents/{doc_id}", headers={"X-API-Key": owner})
            assert got.json()["status"] == "purged" and body not in got.text
            records = c.get(f"{base}/documents/{doc_id}/audit",
                            headers={"X-API-Key": owner}).json()["records"]
            actions = [r["action"] for r in records]
            assert actions.count("purged") == 1
            assert "opened" not in actions and "handover_confirmed" not in actions
            inv = c.get(f"{base}/handover-invitations/{inv_id}",
                        headers={"X-API-Key": owner}).json()
            assert inv["status"] == "expired"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


# ---------------------------------------------------------------------------
# 旧库迁移：无 purge 列 / 旧 CHECK 约束的库幂等升级
# ---------------------------------------------------------------------------


def test_init_db_migrates_old_schema(tmp_path):
    from app.db import init_db

    db = tmp_path / "old.db"
    conn = sqlite3.connect(str(db))
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
                            key_hash TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE documents (
            id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id),
            body TEXT NOT NULL, digest TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('sealed', 'opened')),
            opened_at TEXT, created_at TEXT NOT NULL);
        CREATE TABLE document_witnesses (
            id INTEGER PRIMARY KEY,
            document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id), position INTEGER NOT NULL,
            UNIQUE(document_id, user_id));
        CREATE TABLE open_requests (
            id INTEGER PRIMARY KEY, document_id INTEGER NOT NULL REFERENCES documents(id),
            reason TEXT NOT NULL, deadline TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('pending','opened','revoked','expired')),
            created_at TEXT NOT NULL, resolved_at TEXT);
        CREATE TABLE approvals (
            id INTEGER PRIMARY KEY,
            request_id INTEGER NOT NULL REFERENCES open_requests(id) ON DELETE CASCADE,
            witness_id INTEGER NOT NULL REFERENCES users(id),
            bound_digest TEXT NOT NULL, created_at TEXT NOT NULL,
            UNIQUE(request_id, witness_id));
        """
    )
    conn.execute("INSERT INTO users VALUES (1, 'a', 'h', 't')")
    conn.execute("INSERT INTO documents VALUES (1, 1, 'BODY', 'dg', 'sealed', NULL, 't')")
    conn.execute("INSERT INTO document_witnesses VALUES (1, 1, 1, 0)")
    conn.execute("INSERT INTO open_requests VALUES (1, 1, 'r', 'dl', 'pending', 't', NULL)")
    conn.execute("INSERT INTO approvals VALUES (1, 1, 1, 'dg', 't')")
    conn.commit()
    conn.close()

    init_db(str(db))
    init_db(str(db))  # 幂等

    conn = sqlite3.connect(str(db))
    doc_cols = [r[1] for r in conn.execute("PRAGMA table_info(documents)")]
    assert "purge_at" in doc_cols and "purged_at" in doc_cols
    req_cols = [r[1] for r in conn.execute("PRAGMA table_info(open_requests)")]
    assert "earliest_open_at" in req_cols
    # 数据保留；新状态可用；非法状态仍被拒
    assert conn.execute("SELECT body, status FROM documents WHERE id=1").fetchone() == ("BODY", "sealed")
    assert conn.execute("SELECT COUNT(*) FROM document_witnesses").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM approvals").fetchone()[0] == 1
    conn.execute("UPDATE documents SET status='purged', body='', purged_at='x' WHERE id=1")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE documents SET status='bogus' WHERE id=1")
    conn.close()


# ---------------------------------------------------------------------------
# 时间竞态：改期/取消的时间判定以取得写锁后的实际时刻为准
#
# 请求在旧清除时刻之前到达、等待 BEGIN IMMEDIATE 写锁期间旧时刻已到的，
# 取锁后先按既有顺序结算到点开封与清除（同刻清除优先），再沿用 409 拒绝
# 改期/取消，不得覆盖已到期清除；新提交时刻取锁后已非未来的沿用 400 且
# 不改变原计划。结算、审计与通知必须落库。
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _held_write_lock():
    """在测试进程内占用同一数据库文件的写锁，模拟“请求已到达、等待写锁”窗口。"""
    conn = sqlite3.connect(os.environ["SEAL_DB_PATH"], timeout=30.0)
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
    finally:
        conn.rollback()
        conn.close()


@pytest.fixture
def _no_sweeper(monkeypatch):
    """停用后台扫描器：越过清除时刻的结算必须由被测请求自身在取锁后完成。"""
    from app.main import ExpirySweeper

    monkeypatch.setattr(ExpirySweeper, "sweep_once", staticmethod(lambda: 0))
    time.sleep(0.2)  # 让进行中的扫描收尾（测试扫描间隔 0.05s）


def _raw_db():
    conn = sqlite3.connect(os.environ["SEAL_DB_PATH"])
    conn.row_factory = sqlite3.Row
    return conn


def _assert_fully_purged(conn, doc_id, *, purge_at, request_id=None, invitation=False):
    """清除结算落库：正文清空、purged_at=约定时刻、请求失效旧票删除、邀请逾期。"""
    row = conn.execute(
        "SELECT status, body, purged_at FROM documents WHERE id=?", (doc_id,)
    ).fetchone()
    assert row["status"] == "purged" and row["body"] == ""
    assert row["purged_at"] == purge_at
    if request_id is not None:
        assert conn.execute(
            "SELECT status FROM open_requests WHERE id=?", (request_id,)
        ).fetchone()["status"] == "invalidated"
        assert conn.execute(
            "SELECT COUNT(*) FROM approvals WHERE request_id=?", (request_id,)
        ).fetchone()[0] == 0
    if invitation:
        assert conn.execute(
            "SELECT status FROM handover_invitations WHERE document_id=?", (doc_id,)
        ).fetchone()["status"] == "expired"
    # 审计与 purged 通知已落库
    assert conn.execute(
        "SELECT COUNT(*) FROM audit_log WHERE document_id=? AND action='purged'",
        (doc_id,),
    ).fetchone()[0] == 1
    assert conn.execute(
        "SELECT COUNT(*) FROM notifications WHERE document_id=? AND event_type='purged'",
        (doc_id,),
    ).fetchone()[0] == 4


def _blocking(client, fn):
    """在独立线程发起会阻塞在 BEGIN IMMEDIATE 的请求，返回 (线程, 结果字典)。"""
    import threading

    outcome: dict = {}

    def run():
        r = fn()
        outcome["status"] = r.status_code
        outcome["detail"] = r.json().get("detail")
        outcome["body"] = r.text

    t = threading.Thread(target=run)
    return t, outcome


def test_reschedule_waiting_past_old_purge_purges_then_rejects(client, _no_sweeper):
    """改期在旧清除时刻前到达、取锁时旧时刻已到：先结算清除（请求失效、邀请
    逾期、审计/通知落库），再沿用 409；新时刻不得覆盖已到期清除。"""
    import threading

    keys, doc_id, dg = _setup(client)
    old_purge = _put_purge(client, keys["owner"], doc_id, _in_seconds(1.0)).json()["purge_at"]
    # 一个进行中开封请求（1 票）与一份待确认交接邀请：清除时须连带失效
    req = _create_request(client, keys["owner"], doc_id)["request_id"]
    assert _approve(client, keys["w1"], req, dg).status_code == 200
    inv = client.post(
        f"/documents/{doc_id}/handover-invitations",
        json={"to_username": "new", "confirm_deadline": _in_hours(1)},
        headers=auth(keys["owner"]),
    ).json()["invitation_id"]

    t, outcome = _blocking(client, lambda: _put_purge(client, keys["owner"], doc_id, _in_hours(24)))
    with _held_write_lock():
        t.start()
        time.sleep(1.6)  # 改期等待写锁期间越过 1.0s 的旧清除时刻
    t.join(10)

    assert outcome["status"] == 409
    assert outcome["detail"] == "资料已清除，不能再安排或改期清除"
    assert BODY not in outcome["body"]

    # purge_at 仍是旧时刻、正文已清空（没有被改到 24 小时后）
    with _raw_db() as conn:
        row = conn.execute(
            "SELECT purge_at FROM documents WHERE id=?", (doc_id,)
        ).fetchone()
        assert row["purge_at"] == old_purge
        _assert_fully_purged(
            conn, doc_id, purge_at=old_purge, request_id=req, invitation=True
        )
        # 不得留下改期审计
        assert conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action='purge_rescheduled'"
        ).fetchone()[0] == 0
        purged_at = conn.execute(
            "SELECT at FROM audit_log WHERE document_id=? AND action='purged'",
            (doc_id,),
        ).fetchone()[0]
        # 审计时刻为实际结算时刻：不早于约定清除时刻（绝不记在到期之前）；
        # purged_at 则记为约定清除时刻（已在 _assert_fully_purged 内断言）。
        assert purged_at >= old_purge
        # 实际结算时刻不早于约定清除时刻（绝不把处理时刻记在到期之前）
        assert conn.execute(
            "SELECT resolved_at FROM open_requests WHERE id=?", (req,)
        ).fetchone()[0] >= old_purge

    # 邀请状态对外可见为 expired
    assert client.get(
        f"/handover-invitations/{inv}", headers=auth(keys["owner"])
    ).json()["status"] == "expired"


def test_cancel_waiting_past_old_purge_purges_then_rejects(client, _no_sweeper):
    """取消在旧清除时刻前到达、取锁时旧时刻已到：先结算清除落库，再沿用 409；
    不得把到期清除取消。"""
    import threading

    keys, doc_id, dg = _setup(client)
    old_purge = _put_purge(client, keys["owner"], doc_id, _in_seconds(1.0)).json()["purge_at"]
    req = _create_request(client, keys["owner"], doc_id)["request_id"]
    assert _approve(client, keys["w1"], req, dg).status_code == 200
    inv = client.post(
        f"/documents/{doc_id}/handover-invitations",
        json={"to_username": "new", "confirm_deadline": _in_hours(1)},
        headers=auth(keys["owner"]),
    ).json()["invitation_id"]

    t, outcome = _blocking(client, lambda: _del_purge(client, keys["owner"], doc_id))
    with _held_write_lock():
        t.start()
        time.sleep(1.6)  # 取消等待写锁期间越过 1.0s 的旧清除时刻
    t.join(10)

    assert outcome["status"] == 409
    assert outcome["detail"] == "资料已清除，不能取消清除"
    assert BODY not in outcome["body"]

    with _raw_db() as conn:
        # 清除未被取消：purge_at 保留、purged 已生效、无取消审计
        assert conn.execute(
            "SELECT purge_at FROM documents WHERE id=?", (doc_id,)
        ).fetchone()["purge_at"] == old_purge
        _assert_fully_purged(
            conn, doc_id, purge_at=old_purge, request_id=req, invitation=True
        )
        assert conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action='purge_canceled'"
        ).fetchone()[0] == 0

    assert client.get(
        f"/handover-invitations/{inv}", headers=auth(keys["owner"])
    ).json()["status"] == "expired"


def test_reschedule_new_time_becomes_past_while_waiting_rejects_400(client, _no_sweeper):
    """旧计划仍在未来，但新提交的 purge_at 在等待写锁期间变为非未来：沿用 400
    拒绝且不改变原计划（不触发清除）；截止前取锁的操作不受影响。"""
    import threading

    keys, doc_id, _ = _setup(client)
    old_purge = _in_hours(5)
    assert _put_purge(client, keys["owner"], doc_id, old_purge).status_code == 200

    # 新时刻只在 1.0s 后；持锁 1.6s 使其在取锁后已非未来，但旧计划（5h）远未到
    new_purge = _in_seconds(1.0)
    t, outcome = _blocking(client, lambda: _put_purge(client, keys["owner"], doc_id, new_purge))
    with _held_write_lock():
        t.start()
        time.sleep(1.6)
    t.join(10)

    assert outcome["status"] == 400
    assert outcome["detail"] == "清除时刻必须晚于当前时间"
    assert BODY not in outcome["body"]

    with _raw_db() as conn:
        row = conn.execute(
            "SELECT status, body, purge_at FROM documents WHERE id=?", (doc_id,)
        ).fetchone()
        # 原计划不变、正文保留、资料未清除
        assert row["status"] == "sealed" and row["body"] == BODY
        assert row["purge_at"] == old_purge
        assert conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE document_id=? AND action='purged'",
            (doc_id,),
        ).fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action='purge_rescheduled'"
        ).fetchone()[0] == 0


def test_reschedule_before_old_purge_with_lock_before_deadline_succeeds(client, _no_sweeper):
    """截止（旧清除时刻）之前取得写锁：即使锁内停留到旧时刻之后才提交，只要
    取锁瞬间旧时刻未到，仍按现有规则完成改期（新时刻须为锁内未来时刻）。"""
    import threading

    keys, doc_id, _ = _setup(client)
    old_purge = _in_seconds(3.0)
    assert _put_purge(client, keys["owner"], doc_id, old_purge).status_code == 200

    # 新时刻给足余量；持锁 1.2s 释放——取锁时旧计划（3s）与新时刻（6h）都在未来
    t, outcome = _blocking(client, lambda: _put_purge(client, keys["owner"], doc_id, _in_hours(6)))
    with _held_write_lock():
        t.start()
        time.sleep(1.2)
    t.join(10)

    assert outcome["status"] == 200, outcome.get("body")
    with _raw_db() as conn:
        row = conn.execute(
            "SELECT status, body FROM documents WHERE id=?", (doc_id,)
        ).fetchone()
        assert row["status"] == "sealed" and row["body"] == BODY
        assert conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action='purge_rescheduled'"
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action='purged'"
        ).fetchone()[0] == 0


def test_reschedule_waiting_past_old_purge_same_time_purge_wins(client, _no_sweeper):
    """等待写锁期间旧清除时刻与最早开封时刻同刻到达：同刻清除优先——不开封，
    请求随清除失效，改期仍 409。"""
    import threading

    keys, doc_id, dg = _setup(client)
    same_t = _put_purge(client, keys["owner"], doc_id, _in_seconds(1.0)).json()["purge_at"]
    req = client.post(
        f"/documents/{doc_id}/open-requests",
        json={"reason": "同刻", "deadline": _in_hours(2), "earliest_open_at": same_t},
        headers=auth(keys["owner"]),
    ).json()["request_id"]
    assert _approve(client, keys["w1"], req, dg).status_code == 200
    assert _approve(client, keys["w2"], req, dg).status_code == 200  # waiting

    t, outcome = _blocking(client, lambda: _put_purge(client, keys["owner"], doc_id, _in_hours(24)))
    with _held_write_lock():
        t.start()
        time.sleep(1.6)  # 同刻时刻在等待期间流逝
    t.join(10)

    assert outcome["status"] == 409 and BODY not in outcome["body"]
    with _raw_db() as conn:
        assert conn.execute(
            "SELECT status FROM documents WHERE id=?", (doc_id,)
        ).fetchone()["status"] == "purged"
        # 同刻清除优先：不开封；请求随清除 invalidated
        assert conn.execute(
            "SELECT status FROM open_requests WHERE id=?", (req,)
        ).fetchone()["status"] == "invalidated"
        actions = [
            r["action"]
            for r in conn.execute(
                "SELECT action FROM audit_log WHERE document_id=? ORDER BY id", (doc_id,)
            ).fetchall()
        ]
        assert "opened" not in actions and actions.count("purged") == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM notifications WHERE event_type='opened'"
        ).fetchone()[0] == 0


def test_reschedule_with_invalid_key_does_not_settle(client, _no_sweeper):
    """失效密钥仍先返回既有 401：不触发到点清除结算、不留审计/通知。"""
    import threading

    keys, doc_id, _ = _setup(client)
    assert _put_purge(client, keys["owner"], doc_id, _in_seconds(1.0)).status_code == 200
    # 轮换使旧密钥失效
    rotated = client.post(
        "/me/api-key/rotate", headers=auth(keys["owner"])
    ).json()["api_key"]

    t, outcome = _blocking(
        client, lambda: _put_purge(client, keys["owner"], doc_id, _in_hours(24))
    )
    with _held_write_lock():
        t.start()
        time.sleep(1.6)  # 清除时刻在等待期间流逝
    t.join(10)

    assert outcome["status"] == 401
    with _raw_db() as conn:
        # 旧密钥的改期未触发结算；新密钥仍可查（读路径随后确定性清除）
        row = conn.execute(
            "SELECT status FROM documents WHERE id=?", (doc_id,)
        ).fetchone()
        assert row["status"] == "sealed"
        assert conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE document_id=? AND action='purged'",
            (doc_id,),
        ).fetchone()[0] == 0
    # 新密钥照常工作
    assert _get(client, rotated, doc_id).json()["status"] == "purged"


def test_cancel_without_schedule_after_due_settlement_still_commits(client, _no_sweeper):
    """另一份资料在取消临界区等待期间到点：取消的资料无清除安排（409），
    但另一份资料的到期清除仍随本事务提交落库。"""
    import threading

    keys, doc_id, _ = _setup(client)
    # 第二份资料安排 1s 后清除
    other = seal(client, keys["owner"], BODY + "2", ["w1", "w2", "w3"])
    other_id = other["document_id"]
    assert _put_purge(client, keys["owner"], other_id, _in_seconds(1.0)).status_code == 200

    t, outcome = _blocking(client, lambda: _del_purge(client, keys["owner"], doc_id))
    with _held_write_lock():
        t.start()
        time.sleep(1.6)  # 另一份资料的清除时刻在等待期间流逝
    t.join(10)

    # doc_id 从未安排清除 -> 409
    assert outcome["status"] == 409
    assert outcome["detail"] == "当前没有已安排的清除时刻"
    # 但另一份资料的清除已随本临界区先提交
    with _raw_db() as conn:
        row = conn.execute(
            "SELECT status, body FROM documents WHERE id=?", (other_id,)
        ).fetchone()
        assert row["status"] == "purged" and row["body"] == ""
