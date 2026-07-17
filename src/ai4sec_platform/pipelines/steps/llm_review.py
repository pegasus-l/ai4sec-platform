from __future__ import annotations

from dataclasses import dataclass

from ai4sec_platform.models.router import LLMRouter
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class LlmReviewStep:
    name: str = "llm_review"
    step_type: str = "llm_review"
    input_key: str = "content_items"
    output_key: str = "reviewed_items"
    model_profile: str = "local_rules"
    prompt: str = "请对输入内容进行结构化本地规则处理。"

    def run(self, context: PipelineContext) -> StepResult:
        router = LLMRouter()
        reviewed = []
        for item in list(context.outputs.get(self.input_key) or []):
            if not isinstance(item, dict):
                continue
            reviewed.append({**item, "review": router.complete_json(profile=self.model_profile, prompt=self.prompt, payload=item)})
        context.outputs[self.output_key] = reviewed
        return StepResult(metrics={"reviewed": len(reviewed), "output_key": self.output_key})
