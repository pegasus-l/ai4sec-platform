"""研究复现(writeup 复现):从漏洞素材里挑出"可能真能跑起来"的 writeup。

这一层只做**规则**,不调模型、不碰数据库:

- ``screener_rules`` —— L0/L1 结构规则,纯函数,对同一段文本永远给同一个答案;
- 后续的 ``screener``(L2)才会把过了规则层的素材送模型抽 target/spec。

为什么先把规则写死:同一批 1223 条素材,用"代码块里有可执行命令"这一句自然语言
去量,能得出 145 也能得出 225 —— 差别全在"什么算命令"。规则必须落在代码里,
否则后面所有人对"有多少 writeup 能复现"各说各话。
"""

from ai4sec_platform.domains.capabilities.writeup_repro.screener_rules import (
    BLOCK_KINDS,
    REJECT_REASONS,
    SCREENER_VERSION,
    Block,
    RuleScreen,
    classify_block,
    normalize_repo,
    screen_rules,
    split_blocks,
)

__all__ = [
    "BLOCK_KINDS",
    "REJECT_REASONS",
    "SCREENER_VERSION",
    "Block",
    "RuleScreen",
    "classify_block",
    "normalize_repo",
    "screen_rules",
    "split_blocks",
]
