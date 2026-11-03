"""`deploy/eval/recipes/*.json` —— 预置 recipe 的体检。

为什么值得单测一份 JSON: 这些文件**不经过适配 agent**, 是手写进镜像的(`Dockerfile` 里
`COPY recipes/ ./recipes/`)。手写的配置最容易犯三种错, 而三种都只在部署之后才炸:

  1. 结构不合规(缺 invoke / parser 写错) ⇒ 执行位在收件阶段就拒;
  2. 引用了镜像里不存在的文件(比如 fixture 改了名) ⇒ 跑到一半 rc=2, 看着像工具坏了;
  3. 占位符拼错(`{sample_path}` 之类) ⇒ 参数原样传进去, 工具报"文件不存在"。

这里把三条都按"文件存在 + 能渲染 + 结构合规"查一遍, 不需要真跑工具。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from deploy.eval import adapter
from deploy.eval import runner

RECIPES = Path(__file__).resolve().parents[2] / "deploy" / "eval" / "recipes"
FIXTURES = Path(__file__).resolve().parents[2] / "deploy" / "eval" / "fixtures"
RECIPE_FILES = sorted(RECIPES.glob("*.json"))


def _shadow_of(path: str) -> Path | None:
    """镜像里的 `/opt/eval/fixtures/x.py` 在仓库里是 `deploy/eval/fixtures/x.py`。"""
    prefix = "/opt/eval/fixtures/"
    if path.startswith(prefix):
        return FIXTURES / path[len(prefix):]
    return None


def test_there_is_at_least_one_preset_recipe():
    assert RECIPE_FILES, f"{RECIPES} 下没有任何预置 recipe"


@pytest.mark.parametrize("path", RECIPE_FILES, ids=lambda p: p.name)
def test_preset_recipe_is_structurally_valid(path: Path, tmp_path):
    recipe = json.loads(path.read_text(encoding="utf-8"))
    # 空 tool_version 是允许的: 由 adapter.stamp_version 用工具目录指纹补上;
    # 手写一个没核过的版本号反而会让"换了版本就重探"失效。
    stamped = adapter.stamp_version(recipe, tmp_path)
    assert adapter.validate_recipe(stamped) == []
    assert stamped["tool_version"]


@pytest.mark.parametrize("path", RECIPE_FILES, ids=lambda p: p.name)
def test_placeholders_are_renderable_and_known(path: Path):
    recipe = json.loads(path.read_text(encoding="utf-8"))
    # 只认 runner 真正会替换的那几个名字 —— 拼错一个, 参数就会原样带着 `{...}` 传给工具
    known = {"sample_file", "sample_key", "file_name", "relative_path", "workdir",
             "tool_dir", "prompt", "sample_content",
             "llm_base_url", "llm_api_key", "llm_model"}
    text = json.dumps(recipe.get("invoke") or [], ensure_ascii=False)
    text += json.dumps(recipe.get("install") or [], ensure_ascii=False)
    used = {part.split("}", 1)[0] for part in text.split("{")[1:] if "}" in part}
    assert used <= known, f"未知占位符: {sorted(used - known)}"

    values = {name: f"<{name}>" for name in known}
    rendered = runner.render([str(x) for x in recipe.get("invoke") or []], values)
    for arg in rendered:
        assert "{" not in arg and "}" not in arg, arg


@pytest.mark.parametrize("path", RECIPE_FILES, ids=lambda p: p.name)
def test_files_the_recipe_points_at_exist_in_the_image(path: Path):
    recipe = json.loads(path.read_text(encoding="utf-8"))
    for arg in recipe.get("invoke") or []:
        shadow = _shadow_of(arg)
        if shadow is not None:
            assert shadow.is_file(), f"{path.name} 指向的 {arg} 在仓库里不存在: {shadow}"


def test_openant_recipe_declares_the_parts_the_shim_depends_on():
    """OpenAnt 这份 recipe 有三处是"写错了分数就不可信"的地方, 逐条钉住。

    · 退出码 3 必须声明成 excluded —— 否则不支持的语言会被算成"没找到";
    · out 目录要按 sample_key 分, 否则多份样本互相覆盖对方的产物;
    · 语言不支持时 shim 不交答卷, 所以 ok_exit_codes 里不能有 3。
    """
    recipe = json.loads((RECIPES / "openant.json").read_text(encoding="utf-8"))
    assert recipe["exclude_exit_codes"] == {"3": "language_not_supported"}
    assert 3 not in (recipe.get("ok_exit_codes") or [])
    assert recipe["ok_exit_codes"] == [0]
    invoke = recipe["invoke"]
    assert "{sample_key}" in invoke[invoke.index("--out") + 1]
    # 必须是规范名 `json`: runner 还认老的 `json_stdout`(库里已有的配置不能因为改名失效),
    # 但 `validate_recipe` / `store.save_recipe` **只收规范名** —— 写别名等于这份 recipe
    # 永远冻不进库, 只能靠 FALLBACK_RECIPE 那条旁路跑起来。
    assert recipe["output_parser"] == {"kind": "json"}
