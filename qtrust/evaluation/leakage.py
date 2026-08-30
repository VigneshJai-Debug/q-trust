"""
Leakage checks — §29.

Verifies repository/organization/host disjointness between splits.
Fails the run if leakage detected (CI gate).
"""
from __future__ import annotations

from typing import Any, Dict, List, Set


def check_repo_leakage(train: List[Dict[str, Any]], test: List[Dict[str, Any]], key: str = "repo") -> Dict[str, Any]:
    train_repos: Set[str] = {str(it.get(key)) for it in train}
    test_repos: Set[str] = {str(it.get(key)) for it in test}
    overlap = train_repos & test_repos
    return {"leakage": bool(overlap), "overlap": sorted(overlap), "train_repos": len(train_repos), "test_repos": len(test_repos)}


def check_host_leakage(train: List[Dict[str, Any]], test: List[Dict[str, Any]]) -> Dict[str, Any]:
    return check_repo_leakage(train, test, key="host")


def assert_no_leakage(train, test, key="repo") -> None:
    res = check_repo_leakage(train, test, key=key)
    assert not res["leakage"], f"LEAKAGE detected on {key}: {res['overlap']}"
