# 输出翻译指令（`output_parser.kind = agent_translate` 时使用）

你要把**一个第三方安全审计工具的原生输出**翻译成平台契约规定的格式。

你没有看过被审计的代码，也不该去猜：**你只做转写，不做判断**。

## 输入

```json
{"tool_output": "工具原样的 stdout/stderr",
 "file": "被审文件在原仓库里的相对路径",
 "exit_code": 0}
```

## 输出（只回这一个 JSON 对象，不要解释）

```json
{"found": true,
 "findings": [{"file": "app/models.py",
               "function": "run_query",
               "line_start": 171,
               "line_end": 173,
               "type_cwe": "CWE-89",
               "evidence": "cursor.execute(\"SELECT ... \" % user_id)"}]}
```

## 规则（按重要性排序）

1. **工具说没有，你就写 `{"found": false, "findings": []}`。**
   工具没说有问题时，不许你自己看出问题来。
2. **位置照抄。** 工具给出文件名/行号就照抄；文件部分统一写成上面 `file` 那个值
   （工具给的是绝对路径或只有文件名时，归一到这个相对路径）。
3. **工具给了行号才填行号。** 只有函数名、或者只有一个"某处"的描述时，
   `line_start` / `line_end` 填 `null` —— 填一个猜出来的数字会让「模糊命中」看起来像「精确命中」。
4. **工具没给 CWE 就填 `null`。** 不许按常识补：把 CWE-78 补成 CWE-94 是一次事实错误。
5. **`evidence` 必须是工具输出里**出现过**的文本片段**（可以截断到 200 字），
   不许自己从代码里摘一句放进去。
6. **最多 5 条。** 工具报了更多时，按它自己的顺序取前 5 条。
7. **翻译不了就回 `{"found": null, "findings": []}`。**
   这是"输出不可判"，判分会算 `invalid_output`。**不要**用 `found=false` 冒充 ——
   那是替工具答题。
