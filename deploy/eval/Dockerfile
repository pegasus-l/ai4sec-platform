# 评测执行位
#
# 一个**常驻**容器 + 每 run 一个工作目录(照 repro 的既有模型), 不是每任务一个容器:
# 每个 run 起一个容器的话, 20 对样本一轮就是几十次容器创建, 而容器本身不带状态。
#
# 与 repro 沙箱**刻意分开**: 2026-11-02 实测 repro 已 8.85/10 GiB 且 0 个 running 任务,
# 把评测压进去, 一次 OOM 会同时打掉复现页(那类事故 10-29 已经发生过一次)。
#
# 不带任何平台凭证: 只有一条 EVAL_TOKEN, 且它与 repro 的令牌分开配(见 internal_eval.py)。
FROM python:3.11-slim

# git/build-essential: 被测工具多半要 pip install 或编译; 少了它们, 装不上会被
# 记成"工具不可用", 而实际是我们自己的执行位缺组件 —— 这种归因错误最难查。
# curl: 有些工具自带自检脚本依赖它。
# nodejs/npm: 同样属于"工具声称支持的语言要有相应运行时"。OpenAnt 的
#   javascript 解析器是 node 子进程(`parsers/javascript/*.js`), 缺 node 时
#   JS/TS 样本会以"解析失败"计成工具的分数, 而这只是我们没装运行时。
#   注意: 它还需要 `npm install`(ts-morph/typescript), 由 recipe 的 install 跑。
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git build-essential nodejs npm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/eval
COPY runner.py ./runner.py
COPY adapter.py ./adapter.py
COPY prompts/ ./prompts/
COPY fixtures/ ./fixtures/
COPY recipes/ ./recipes/

ENV PYTHONUNBUFFERED=1 \
    EVAL_WORK_ROOT=/work/runs \
    EVAL_TOOL_ROOT=/work/tools \
    EVAL_RECIPE_DIR=/opt/eval/recipes

WORKDIR /work
VOLUME ["/work"]

# oom_score_adj=800(照 750614c 先例): 真到要杀一个的时候, 先杀执行位。
# 平台被杀 = 全站页面 502; 执行位被杀 = 一个评测失败, 下一轮重领即可。
# 只能"调高"(让自己更容易被杀), 所以不需要额外权限。
CMD ["sh", "-c", "echo 800 > /proc/self/oom_score_adj 2>/dev/null; exec python3 -u /opt/eval/runner.py"]
