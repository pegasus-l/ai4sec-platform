"""T1.1 规则层单测。

每条用例都来自线上真实素材的形态(菜单 dump、路径串、地图注释、Solidity PoC…),
不是凭想象造的字符串 —— 规则层的坑全在"长得像代码但不是"这一侧。
"""

from __future__ import annotations

import pytest

from ai4sec_platform.domains.capabilities.writeup_repro import (
    classify_block,
    normalize_repo,
    screen_rules,
    split_blocks,
)


# ─────────────────────────── L0-a:没有代码块 ───────────────────────────

@pytest.mark.parametrize("text", ["", "一篇只有文字的评论,没有代码。"])
def test_no_blocks_is_not_writeup(text: str) -> None:
    r = screen_rules(text)
    assert r.screenable is False
    assert r.reject_reason == "not_writeup"


def test_empty_fence_is_still_a_block_but_has_no_poc() -> None:
    r = screen_rules("```\n\n```")
    assert r.reject_reason == "no_poc"


# ─────────────────────────── L0-b:有块但跑不出东西 ───────────────────────────

def test_program_menu_is_not_a_poc() -> None:
    """实测素材:CTF 菜单被当成代码块。它长得像代码,但敲不出任何东西。"""
    text = "```\n===============\n|   HeapLAB   |\n===============\n1) malloc 0/16\n2) free\n3) edit\n```"
    r = screen_rules(text)
    assert r.screenable is False
    assert r.reject_reason == "no_poc"


def test_bare_path_block_is_not_a_poc() -> None:
    text = "```\n../../../../../../../dev/null\n```"
    assert screen_rules(text).reject_reason == "no_poc"


def test_output_dump_with_hash_comments_is_not_a_command() -> None:
    """回归:输出/地图 dump 里的 ``#  ├── center: ...`` 曾被当成 shell 提示符。"""
    text = (
        "```\n"
        "# [TILE #1]  14:23:07  z=15 x=9649 y=12320\n"
        "#   ├── center: 40.70979, -73.98743\n"
        "#   └── map: https://www.openstreetmap.org/#map=15/40.70979/-73.98743\n"
        "```"
    )
    r = screen_rules(text)
    assert r.reject_reason == "no_poc"
    assert r.has_command is False


def test_c_macro_definitions_are_not_commands() -> None:
    text = "```\n# define IOCTL_MMMAPIOSPACE  0x8000645C\n# define IOCTL_MMMAPIOMEM   0x80006460\n```"
    assert screen_rules(text).has_command is False


# ─────────────────────────── L1:真 PoC ───────────────────────────

def test_shell_commands_plus_repo_is_screenable() -> None:
    text = (
        "复现步骤:\n"
        "```\n"
        "git clone https://github.com/AcademySoftwareFoundation/openapv.git\n"
        "cd openapv\n"
        "git checkout v0.1.11.1\n"
        "```\n"
        "见 https://github.com/AcademySoftwareFoundation/openapv/issues/7\n"
    )
    r = screen_rules(text)
    assert r.screenable is True
    assert r.has_command is True
    assert r.target_repo == "github:academysoftwarefoundation/openapv"
    assert r.reject_reason == ""


def test_root_prompt_hash_line_counts_as_command() -> None:
    text = "```\n# apt install -y build-essential\n```\nCVE-2024-1234 影响该版本 2.17.1。"
    r = screen_rules(text)
    assert r.has_command is True
    assert r.screenable is True


def test_source_block_with_cve_is_screenable() -> None:
    text = (
        "PoC 合约:\n"
        "```solidity\n"
        "pragma solidity ^0.8.13;\n"
        "contract Exploit { function run() external {} }\n"
        "```\n"
        "影响 CVE-2025-0001。\n"
    )
    r = screen_rules(text)
    assert r.screenable is True
    assert r.has_source is True
    assert r.cve_ids == ("CVE-2025-0001",)


def test_c_include_block_is_source_even_without_lang_tag() -> None:
    text = "```\n#include <sys/ioctl.h>\n#include <stdio.h>\n```\n目标 v1.2.3"
    r = screen_rules(text)
    assert r.has_source is True
    assert r.screenable is True


def test_cve_in_title_counts_as_target_clue() -> None:
    """实测:有些文章正文里不写编号,只在标题写 ``CVE-2026-43456``。"""
    text = "```\n$ ./poc --x\n```\n复现方法如下。"
    assert screen_rules(text).reject_reason == "target_unknown"
    r = screen_rules(text, title="Linux kernel 零日 CVE-2026-43456")
    assert r.screenable is True
    assert r.cve_ids == ("CVE-2026-43456",)


def test_url_counts_as_target_clue() -> None:
    text = "```\n$ make && ./run\n```"
    r = screen_rules(text, url="https://github.com/acme/vuln-demo")
    assert r.screenable is True
    assert r.target_repo == "github:acme/vuln-demo"


def test_poc_without_target_is_target_unknown() -> None:
    text = "```\n$ ./poc --target 127.0.0.1\n```\n这个洞影响很多设备。"
    r = screen_rules(text)
    assert r.screenable is False
    assert r.reject_reason == "target_unknown"
    assert r.has_command is True


# ─────────────────────────── 仓库归一 ───────────────────────────

@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://github.com/foo/Bar.git", "github:foo/bar"),
        ("https://gitcode.com/Ascend/MindIE-Motor", "gitcode:ascend/mindie-motor"),
        ("https://github.com/foo/bar/issues/12", "github:foo/bar"),
        ("https://github.com/foo/bar/blob/main/x.c", "github:foo/bar"),
        ("https://blog.example.com/foo/bar", ""),
        ("https://github.com/foo", ""),
        ("", ""),
    ],
)
def test_normalize_repo(raw: str, expected: str) -> None:
    assert normalize_repo(raw) == expected


# ─────────────────────────── 版本与确定性 ───────────────────────────

def test_two_component_version_does_not_count_as_clue() -> None:
    """``1.2`` 在正文里到处都是,不能当"定得下版本"。"""
    r = screen_rules("```\n$ python3 poc.py\n```\n该漏洞影响 1.2 版本。")
    assert r.reject_reason == "target_unknown"
    assert r.versions == ()


def test_three_component_version_counts() -> None:
    r = screen_rules("```\n$ python3 poc.py\n```\n影响 1.2.3 及之前。")
    assert r.screenable is True
    assert "1.2.3" in r.versions


def test_same_text_gives_same_answer() -> None:
    text = "```bash\n$ curl http://x/y\n```\nCVE-2023-1111"
    a, b = screen_rules(text), screen_rules(text)
    assert a == b


def test_block_kinds_reported_for_debugging() -> None:
    blocks = split_blocks("```\n$ ls\n```\n```python\nimport os\n```\n```\nplain output line\n```")
    assert [b.kind for b in blocks] == ["command", "source", "data"]


def test_classify_sh_tagged_block_is_command() -> None:
    assert classify_block("bash", "\n".join(f"echo {i}" for i in range(30))) == "command"
