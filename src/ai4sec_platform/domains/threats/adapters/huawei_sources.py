from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ai4sec_platform.core.concurrency import bounded_map
from ai4sec_platform.domains.threats.security_repo_discovery import discover_security_repos, group_projects_by_org
from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.registry import SourceRegistry

CVE_DIR_TERMS = ["security-disclosure", "advisory", "cve", "vulnerability", "vuln", "漏洞", "安全公告", "安全披露"]
DEFAULT_LIVE_ORGS = [
    {"platform": "gitcode", "org": "Ascend"},
    {"platform": "gitcode", "org": "Cangjie"},
    {"platform": "gitcode", "org": "Cantian"},
    {"platform": "gitcode", "org": "DevCloudFE"},
    {"platform": "gitcode", "org": "ModelEngine"},
    {"platform": "gitcode", "org": "arkui-x"},
    {"platform": "gitcode", "org": "cann"},
    {"platform": "gitcode", "org": "eBackup"},
    {"platform": "gitcode", "org": "huaweicloud"},
    {"platform": "gitcode", "org": "kappital"},
    {"platform": "gitcode", "org": "kunpengcompute"},
    {"platform": "atomgit", "org": "mindspore"},
    {"platform": "gitcode", "org": "openFuyao"},
    {"platform": "gitcode", "org": "openHiTLS"},
    {"platform": "gitcode", "org": "openInula"},
    {"platform": "gitcode", "org": "openJiuwen"},
    {"platform": "gitcode", "org": "openUBMC"},
    {"platform": "atomgit", "org": "openeuler"},
    {"platform": "gitcode", "org": "opengauss"},
    {"platform": "gitcode", "org": "openharmony-sig"},
    {"platform": "gitcode", "org": "openharmony-tpc"},
    {"platform": "gitcode", "org": "openharmony"},
    {"platform": "gitcode", "org": "openkylin"},
    {"platform": "gitcode", "org": "openlookeng"},
    {"platform": "gitcode", "org": "opentiny"},
]
SECURITY_FILE_SUFFIXES = (".md", ".markdown", ".yml", ".yaml", ".json")
SECURITY_FILE_TERMS = ["security", "advisory", "cve", "vulnerability", "vuln", "漏洞", "安全公告", "安全披露"]
SECURITY_SOURCE_CODE_REPO_NAMES = {"cve-manager", "cve-manage", "cve-manage-bot", "cve-ease"}
DEFAULT_ASCENDHUB_TARGETS = [
    {"hub_id": 'af85b724a7e5469ebd7ea13c3439d48f', "name": 'mindie', "url": 'https://www.hiascend.com/developer/ascendhub/detail/af85b724a7e5469ebd7ea13c3439d48f', "label": 'mindie'},
    {"hub_id": 'f1690465f39847a8b0a1f9e5b36a03c4', "name": 'mindie-motor', "url": 'https://www.hiascend.com/developer/ascendhub/detail/f1690465f39847a8b0a1f9e5b36a03c4', "label": 'mindie-motor'},
    {"hub_id": '0bc31428b0984445a39496fdcfce7c2b', "name": 'torch-onnx-inference', "url": 'https://www.hiascend.com/developer/ascendhub/detail/0bc31428b0984445a39496fdcfce7c2b', "label": 'torch-onnx-inference'},
    {"hub_id": '905e08a775514cf9a469f42530cb1cd3', "name": 'mineru2.5-2509-1.2b', "url": 'https://www.hiascend.com/developer/ascendhub/detail/905e08a775514cf9a469f42530cb1cd3', "label": 'mineru2.5-2509-1.2b'},
    {"hub_id": '4ad248a439a44b4bb72e0534bfda8e2a', "name": 'mindspeed-core', "url": 'https://www.hiascend.com/developer/ascendhub/detail/4ad248a439a44b4bb72e0534bfda8e2a', "label": 'mindspeed-core'},
    {"hub_id": 'e26da9266559438b93354792f25b2f4a', "name": 'mindspeed-llm', "url": 'https://www.hiascend.com/developer/ascendhub/detail/e26da9266559438b93354792f25b2f4a', "label": 'mindspeed-llm'},
    {"hub_id": '6857f6fc2cfa4a678710a7075426ee5e', "name": 'mindspeed-mm', "url": 'https://www.hiascend.com/developer/ascendhub/detail/6857f6fc2cfa4a678710a7075426ee5e', "label": 'mindspeed-mm'},
    {"hub_id": '7f91c3663b5d4a97b3ae40e3cabbb3a2', "name": 'indexsdk', "url": 'https://www.hiascend.com/developer/ascendhub/detail/7f91c3663b5d4a97b3ae40e3cabbb3a2', "label": 'indexsdk'},
    {"hub_id": '696b50584fa04d4a8e99f7894f8eb176', "name": 'drivingsdk', "url": 'https://www.hiascend.com/developer/ascendhub/detail/696b50584fa04d4a8e99f7894f8eb176', "label": 'drivingsdk'},
    {"hub_id": 'a592da7bd2ab4dffa8864abd4eac5068', "name": 'ascend-k8sdeviceplugin', "url": 'https://www.hiascend.com/developer/ascendhub/detail/a592da7bd2ab4dffa8864abd4eac5068', "label": 'ascend-k8sdeviceplugin'},
    {"hub_id": '1b1a8c3cc1ff4710bdb0222514a8a7a3', "name": 'npu-exporter', "url": 'https://www.hiascend.com/developer/ascendhub/detail/1b1a8c3cc1ff4710bdb0222514a8a7a3', "label": 'npu-exporter'},
    {"hub_id": 'cc7e6c0a10834f1888d790174fba4bc5', "name": 'noded', "url": 'https://www.hiascend.com/developer/ascendhub/detail/cc7e6c0a10834f1888d790174fba4bc5', "label": 'noded'},
    {"hub_id": 'a066319600634cf6a1e522856a63a1c5', "name": 'ascend-operator', "url": 'https://www.hiascend.com/developer/ascendhub/detail/a066319600634cf6a1e522856a63a1c5', "label": 'ascend-operator'},
    {"hub_id": 'b554929b470747448924bc786b5ab95d', "name": 'clusterd', "url": 'https://www.hiascend.com/developer/ascendhub/detail/b554929b470747448924bc786b5ab95d', "label": 'clusterd'},
    {"hub_id": '9e0edaf9488b447b951072c5c61ce8f1', "name": 'visionsdk', "url": 'https://www.hiascend.com/developer/ascendhub/detail/9e0edaf9488b447b951072c5c61ce8f1', "label": 'visionsdk'},
    {"hub_id": 'e0081aa3c4dd441dbd6a379bee8cc4c9', "name": 'multimodalsdk', "url": 'https://www.hiascend.com/developer/ascendhub/detail/e0081aa3c4dd441dbd6a379bee8cc4c9', "label": 'multimodalsdk'},
    {"hub_id": 'f1b460e88aae4993b8522b611af07100', "name": 'mindformers', "url": 'https://www.hiascend.com/developer/ascendhub/detail/f1b460e88aae4993b8522b611af07100', "label": 'mindformers'},
    {"hub_id": 'b875f781df984480b0385a96fa1b03c9', "name": 'ragsdk', "url": 'https://www.hiascend.com/developer/ascendhub/detail/b875f781df984480b0385a96fa1b03c9', "label": 'ragsdk'},
    {"hub_id": '07a016975cc341f3a5ae131f2b52399d', "name": 'mis-tei', "url": 'https://www.hiascend.com/developer/ascendhub/detail/07a016975cc341f3a5ae131f2b52399d', "label": 'mis-tei'},
    {"hub_id": '54545fa4ff9f446e914bf44b85efdb61', "name": 'vc-scheduler', "url": 'https://www.hiascend.com/developer/ascendhub/detail/54545fa4ff9f446e914bf44b85efdb61', "label": 'vc-scheduler'},
    {"hub_id": '16f17a3c95d54f9da710a9c51bfceaa3', "name": 'vc-controller-manager', "url": 'https://www.hiascend.com/developer/ascendhub/detail/16f17a3c95d54f9da710a9c51bfceaa3', "label": 'vc-controller-manager'},
    {"hub_id": '17da20d1c2b6493cb38765adeba85884', "name": 'cann', "url": 'https://www.hiascend.com/developer/ascendhub/detail/17da20d1c2b6493cb38765adeba85884', "label": 'cann'},
    {"hub_id": 'f412fba48e384edd885d30fd8d3eb36a', "name": 'mineru', "url": 'https://www.hiascend.com/developer/ascendhub/detail/f412fba48e384edd885d30fd8d3eb36a', "label": 'mineru'},
    {"hub_id": '6444819aa26f4a68a892de382ffe7011', "name": 'clip-service', "url": 'https://www.hiascend.com/developer/ascendhub/detail/6444819aa26f4a68a892de382ffe7011', "label": 'clip-service'},
    {"hub_id": '51b1c142d02e411986d439a0bc7ea05b', "name": 'verl_pt27_25rc4', "url": 'https://www.hiascend.com/developer/ascendhub/detail/51b1c142d02e411986d439a0bc7ea05b', "label": 'verl_pt27_25rc4'},
    {"hub_id": '812024b34b0d481e9aed9240e49751e3', "name": 'bailing', "url": 'https://www.hiascend.com/developer/ascendhub/detail/812024b34b0d481e9aed9240e49751e3', "label": 'bailing'},
    {"hub_id": '3e06afa229b44ff3806cf90671e5d356', "name": 'model-agent', "url": 'https://www.hiascend.com/developer/ascendhub/detail/3e06afa229b44ff3806cf90671e5d356', "label": 'model-agent'},
    {"hub_id": '1bb1e5d9c8c64f6ea8db0d0ec5061531', "name": 'torch-npu', "url": 'https://www.hiascend.com/developer/ascendhub/detail/1bb1e5d9c8c64f6ea8db0d0ec5061531', "label": 'torch-npu'},
    {"hub_id": 'e3be9b62ce23426ba1e3b526f12d264d', "name": 'mindspore', "url": 'https://www.hiascend.com/developer/ascendhub/detail/e3be9b62ce23426ba1e3b526f12d264d', "label": 'mindspore'},
    {"hub_id": '13f3dee71712420d8b583b9275c04899', "name": 'infer-operator', "url": 'https://www.hiascend.com/developer/ascendhub/detail/13f3dee71712420d8b583b9275c04899', "label": 'infer-operator'},
    {"hub_id": '9faeb4847b3e419f81b78a4d0ed574b5', "name": 'rec_sdk-torch', "url": 'https://www.hiascend.com/developer/ascendhub/detail/9faeb4847b3e419f81b78a4d0ed574b5', "label": 'rec_sdk-torch'},
    {"hub_id": 'ddde3f36631c4a4eb6edc1ced0cd7ca0', "name": 'milvus', "url": 'https://www.hiascend.com/developer/ascendhub/detail/ddde3f36631c4a4eb6edc1ced0cd7ca0', "label": 'milvus'},
    {"hub_id": '013af8991f004f83aee6765b095c8366', "name": 'triton-inference-server-ge-backend', "url": 'https://www.hiascend.com/developer/ascendhub/detail/013af8991f004f83aee6765b095c8366', "label": 'triton-inference-server-ge-backend'},
    {"hub_id": '751214c040ca45948255fed5f1f5fffa', "name": 'cosyvoice2-0.5b', "url": 'https://www.hiascend.com/developer/ascendhub/detail/751214c040ca45948255fed5f1f5fffa', "label": 'cosyvoice2-0.5b'},
    {"hub_id": '672a0d8d944b480f9adcec742a1947f5', "name": 'groundingdino', "url": 'https://www.hiascend.com/developer/ascendhub/detail/672a0d8d944b480f9adcec742a1947f5', "label": 'groundingdino'},
    {"hub_id": 'ac6c4cdfd0e64876bbdaabfe1a577853', "name": 'paddleocr-vl', "url": 'https://www.hiascend.com/developer/ascendhub/detail/ac6c4cdfd0e64876bbdaabfe1a577853', "label": 'paddleocr-vl'},
    {"hub_id": 'f86b40964e604ff99845976440fe5ca3', "name": 'qwen3-235b-a22b-w8a8', "url": 'https://www.hiascend.com/developer/ascendhub/detail/f86b40964e604ff99845976440fe5ca3', "label": 'qwen3-235b-a22b-w8a8'},
    {"hub_id": '3676fccd38ea4d4494da6f7874af13f3', "name": 'qwen3-coder-30b-a3b-instruct', "url": 'https://www.hiascend.com/developer/ascendhub/detail/3676fccd38ea4d4494da6f7874af13f3', "label": 'qwen3-coder-30b-a3b-instruct'},
    {"hub_id": '9f6bcccfec5c4442bc780b456f55bcce', "name": 'qwen3-vl-32b-instruct', "url": 'https://www.hiascend.com/developer/ascendhub/detail/9f6bcccfec5c4442bc780b456f55bcce', "label": 'qwen3-vl-32b-instruct'},
    {"hub_id": '123b687bbc874c4c83ed68d0506bfcb2', "name": 'sensevoice-small', "url": 'https://www.hiascend.com/developer/ascendhub/detail/123b687bbc874c4c83ed68d0506bfcb2', "label": 'sensevoice-small'},
    {"hub_id": '1672e8a29bd84a97a89912e68e2fbc27', "name": 'whisper-large-v3', "url": 'https://www.hiascend.com/developer/ascendhub/detail/1672e8a29bd84a97a89912e68e2fbc27', "label": 'whisper-large-v3'},
    {"hub_id": '382bd1f3672d4407aa93721fe03d39ff', "name": 'yolov12l', "url": 'https://www.hiascend.com/developer/ascendhub/detail/382bd1f3672d4407aa93721fe03d39ff', "label": 'yolov12l'},
    {"hub_id": '4094ae345afb420fb7491bbac1607f8c', "name": 'yolov12x', "url": 'https://www.hiascend.com/developer/ascendhub/detail/4094ae345afb420fb7491bbac1607f8c', "label": 'yolov12x'},
    {"hub_id": '5faf337534c847f0b135a52af924bbf4', "name": 'openclaw', "url": 'https://www.hiascend.com/developer/ascendhub/detail/5faf337534c847f0b135a52af924bbf4', "label": 'openclaw'},
    {"hub_id": 'a4411ed8c56a4a858a57732051456b80', "name": 'hccl-controller', "url": 'https://www.hiascend.com/developer/ascendhub/detail/a4411ed8c56a4a858a57732051456b80', "label": 'hccl-controller'},
    {"hub_id": 'a970c3734a2a44fd91ddc55c50430f88', "name": 'qwen3-14b', "url": 'https://www.hiascend.com/developer/ascendhub/detail/a970c3734a2a44fd91ddc55c50430f88', "label": 'qwen3-14b'},
    {"hub_id": '39730c7af872464ba25be1c2ce15915f', "name": 'ascend-pytorch', "url": 'https://www.hiascend.com/developer/ascendhub/detail/39730c7af872464ba25be1c2ce15915f', "label": 'ascend-pytorch'},
    {"hub_id": 'd0b726158220405f98bd9b0ba9cbb6a1', "name": 'vit-b-16', "url": 'https://www.hiascend.com/developer/ascendhub/detail/d0b726158220405f98bd9b0ba9cbb6a1', "label": 'vit-b-16'},
    {"hub_id": 'c8cd59042c7f45e6bd1702ee6f27c905', "name": 'rec_sdk-tf1', "url": 'https://www.hiascend.com/developer/ascendhub/detail/c8cd59042c7f45e6bd1702ee6f27c905', "label": 'rec_sdk-tf1'},
    {"hub_id": '99a60e73d14b492888a721a417928487', "name": 'rec_sdk-tf2', "url": 'https://www.hiascend.com/developer/ascendhub/detail/99a60e73d14b492888a721a417928487', "label": 'rec_sdk-tf2'},
    {"hub_id": '2c7122f323f94a19ba7fca6b8dccf11e', "name": 'verl_pt27_2025rc3', "url": 'https://www.hiascend.com/developer/ascendhub/detail/2c7122f323f94a19ba7fca6b8dccf11e', "label": 'verl_pt27_2025rc3'},
    {"hub_id": 'c2af83dd092a417aafe833991fb6acc0', "name": 'mindspeed_rl_pt25_25rc3', "url": 'https://www.hiascend.com/developer/ascendhub/detail/c2af83dd092a417aafe833991fb6acc0', "label": 'mindspeed_rl_pt25_25rc3'},
    {"hub_id": '2a71f71cb92643baa95e527b39088e0e', "name": 'verl_pt27_25rc3', "url": 'https://www.hiascend.com/developer/ascendhub/detail/2a71f71cb92643baa95e527b39088e0e', "label": 'verl_pt27_25rc3'},
    {"hub_id": '347c97e4a48743c486a2fc7e1d2444d7', "name": 'bge-large-zh-v1.5', "url": 'https://www.hiascend.com/developer/ascendhub/detail/347c97e4a48743c486a2fc7e1d2444d7', "label": 'bge-large-zh-v1.5'},
    {"hub_id": 'eb20cc90aebb4b4580596dde93983f96', "name": 'bge-m3', "url": 'https://www.hiascend.com/developer/ascendhub/detail/eb20cc90aebb4b4580596dde93983f96', "label": 'bge-m3'},
    {"hub_id": '4c1b3ae5603c4e6580f1dcf158ba13b2', "name": 'bge-reranker-large', "url": 'https://www.hiascend.com/developer/ascendhub/detail/4c1b3ae5603c4e6580f1dcf158ba13b2', "label": 'bge-reranker-large'},
    {"hub_id": '0ec47fdcbb3a4634bbdcbcc0f8b2f5ce', "name": 'bge-reranker-v2-m3', "url": 'https://www.hiascend.com/developer/ascendhub/detail/0ec47fdcbb3a4634bbdcbcc0f8b2f5ce', "label": 'bge-reranker-v2-m3'},
    {"hub_id": 'dbb2d5af151f43a687d2b53ea61dcaff', "name": 'deepseek-r1-distill-llama-70b', "url": 'https://www.hiascend.com/developer/ascendhub/detail/dbb2d5af151f43a687d2b53ea61dcaff', "label": 'deepseek-r1-distill-llama-70b'},
    {"hub_id": '5ad498f197c94aec8f29fa600866e954', "name": 'deepseek-r1-distill-llama-8b', "url": 'https://www.hiascend.com/developer/ascendhub/detail/5ad498f197c94aec8f29fa600866e954', "label": 'deepseek-r1-distill-llama-8b'},
    {"hub_id": 'b4598e6a1ecc408faa7b1af224f7a645', "name": 'deepseek-r1-distill-qwen-1.5b', "url": 'https://www.hiascend.com/developer/ascendhub/detail/b4598e6a1ecc408faa7b1af224f7a645', "label": 'deepseek-r1-distill-qwen-1.5b'},
    {"hub_id": 'c4cbc68122b94f5d87391d3bc97720c5', "name": 'deepseek-r1-distill-qwen-14b', "url": 'https://www.hiascend.com/developer/ascendhub/detail/c4cbc68122b94f5d87391d3bc97720c5', "label": 'deepseek-r1-distill-qwen-14b'},
    {"hub_id": '2f6eefd0a73941c993ca39b7f6912603', "name": 'ubuntu', "url": 'https://www.hiascend.com/developer/ascendhub/detail/2f6eefd0a73941c993ca39b7f6912603', "label": 'ubuntu'},
    {"hub_id": 'e63fba1767464ba199bb70b02803d03c', "name": 'llama-3.2-1b-instruct', "url": 'https://www.hiascend.com/developer/ascendhub/detail/e63fba1767464ba199bb70b02803d03c', "label": 'llama-3.2-1b-instruct'},
    {"hub_id": 'd5da7274ba244d1c93064680a0e387e3', "name": 'llama-3.2-3b-instruct', "url": 'https://www.hiascend.com/developer/ascendhub/detail/d5da7274ba244d1c93064680a0e387e3', "label": 'llama-3.2-3b-instruct'},
    {"hub_id": '4c9820e2b11042529fa585f582f5db22', "name": 'llama-3.3-70b-instruct', "url": 'https://www.hiascend.com/developer/ascendhub/detail/4c9820e2b11042529fa585f582f5db22', "label": 'llama-3.3-70b-instruct'},
    {"hub_id": '1eacdfbaeb0441d0bb5505b43359756a', "name": 'minicpm-v-2_6', "url": 'https://www.hiascend.com/developer/ascendhub/detail/1eacdfbaeb0441d0bb5505b43359756a', "label": 'minicpm-v-2_6'},
    {"hub_id": '10ec63b3afea4340b7474ee4e1ea450d', "name": 'qwen2.5-0.5b-instruct', "url": 'https://www.hiascend.com/developer/ascendhub/detail/10ec63b3afea4340b7474ee4e1ea450d', "label": 'qwen2.5-0.5b-instruct'},
    {"hub_id": 'c9f15e1428e4465586b471c81a253df0', "name": 'qwen2.5-1.5b-instruct', "url": 'https://www.hiascend.com/developer/ascendhub/detail/c9f15e1428e4465586b471c81a253df0', "label": 'qwen2.5-1.5b-instruct'},
    {"hub_id": '6097015bf36a4054823da97b4d191583', "name": 'qwen2.5-14b-instruct', "url": 'https://www.hiascend.com/developer/ascendhub/detail/6097015bf36a4054823da97b4d191583', "label": 'qwen2.5-14b-instruct'},
    {"hub_id": '125b5fb4e7184b8dabc3ae4b18c6ff99', "name": 'qwen2.5-32b-instruct', "url": 'https://www.hiascend.com/developer/ascendhub/detail/125b5fb4e7184b8dabc3ae4b18c6ff99', "label": 'qwen2.5-32b-instruct'},
    {"hub_id": 'a0b412c2e8ac45d799efb2184174ea99', "name": 'qwen2.5-3b-instruct', "url": 'https://www.hiascend.com/developer/ascendhub/detail/a0b412c2e8ac45d799efb2184174ea99', "label": 'qwen2.5-3b-instruct'},
    {"hub_id": '6b1b02e8c95f44e88b29e520aa688bc8', "name": 'qwen2.5-72b-instruct', "url": 'https://www.hiascend.com/developer/ascendhub/detail/6b1b02e8c95f44e88b29e520aa688bc8', "label": 'qwen2.5-72b-instruct'},
    {"hub_id": '1efc4ce8bfad4e2994adc65f2ed74745', "name": 'qwen2.5-7b-instruct', "url": 'https://www.hiascend.com/developer/ascendhub/detail/1efc4ce8bfad4e2994adc65f2ed74745', "label": 'qwen2.5-7b-instruct'},
    {"hub_id": 'a7e8839b613f4b6d9f91991f9b13e1f4', "name": 'qwen2.5-omni-3b', "url": 'https://www.hiascend.com/developer/ascendhub/detail/a7e8839b613f4b6d9f91991f9b13e1f4', "label": 'qwen2.5-omni-3b'},
    {"hub_id": '686c05fa27434f51871e229005829cd7', "name": 'qwen2.5-omni-7b', "url": 'https://www.hiascend.com/developer/ascendhub/detail/686c05fa27434f51871e229005829cd7', "label": 'qwen2.5-omni-7b'},
    {"hub_id": '3c2cac7ad7f74583bfe419800a71341c', "name": 'qwen2.5-vl-32b-instruct', "url": 'https://www.hiascend.com/developer/ascendhub/detail/3c2cac7ad7f74583bfe419800a71341c', "label": 'qwen2.5-vl-32b-instruct'},
    {"hub_id": '9eedc82e0c0644b2a2a9d0821ed5e7ad', "name": 'qwen2.5-vl-7b-instruct', "url": 'https://www.hiascend.com/developer/ascendhub/detail/9eedc82e0c0644b2a2a9d0821ed5e7ad', "label": 'qwen2.5-vl-7b-instruct'},
    {"hub_id": 'e73d8391097c4fd1b20fb22facd66a46', "name": 'qwen3-8b', "url": 'https://www.hiascend.com/developer/ascendhub/detail/e73d8391097c4fd1b20fb22facd66a46', "label": 'qwen3-8b'},
    {"hub_id": '44d97ca10b0845b582336f2161d1c3a8', "name": 'qwen3-32b', "url": 'https://www.hiascend.com/developer/ascendhub/detail/44d97ca10b0845b582336f2161d1c3a8', "label": 'qwen3-32b'},
    {"hub_id": 'f153b91917ca4e6bbd676a22f3ddb3ac', "name": 'qwq-32b', "url": 'https://www.hiascend.com/developer/ascendhub/detail/f153b91917ca4e6bbd676a22f3ddb3ac', "label": 'qwq-32b'},
    {"hub_id": '8746167c4a4b4f788c142f5067a226f8', "name": 'deepseek-r1-distill-qwen-32b', "url": 'https://www.hiascend.com/developer/ascendhub/detail/8746167c4a4b4f788c142f5067a226f8', "label": 'deepseek-r1-distill-qwen-32b'},
    {"hub_id": '5c613bed40a24bb88bbf352ed9924e88', "name": 'deepseek-r1-distill-qwen-7b', "url": 'https://www.hiascend.com/developer/ascendhub/detail/5c613bed40a24bb88bbf352ed9924e88', "label": 'deepseek-r1-distill-qwen-7b'},
    {"hub_id": '71d13fd83df94c64ae795e317ff98359', "name": 'qwen3-30b-a3b', "url": 'https://www.hiascend.com/developer/ascendhub/detail/71d13fd83df94c64ae795e317ff98359', "label": 'qwen3-30b-a3b'},
    {"hub_id": '9fe650024b4b48ba991c7f22dab11438', "name": 'vit-h-14', "url": 'https://www.hiascend.com/developer/ascendhub/detail/9fe650024b4b48ba991c7f22dab11438', "label": 'vit-h-14'},
    {"hub_id": 'a04c486c9d7c41f1a9b9d21d929d8903', "name": 'resilience-controller', "url": 'https://www.hiascend.com/developer/ascendhub/detail/a04c486c9d7c41f1a9b9d21d929d8903', "label": 'resilience-controller'},
    {"hub_id": '9353d9619c2a44db87845bce546c17bd', "name": 'centos', "url": 'https://www.hiascend.com/developer/ascendhub/detail/9353d9619c2a44db87845bce546c17bd', "label": 'centos'},
]


def load_huawei_sources(settings, params: dict[str, Any]) -> list[dict[str, Any]]:
    resumed = _load_source_records_from_run(settings, params)
    if resumed is not None:
        return resumed
    explicit = _load_source_records_from_path(params)
    if explicit is not None:
        return explicit
    if bool(params.get("use_source_cache", False)) or params.get("refresh_sources") or params.get("sources"):
        return _load_huawei_sources_with_source_cache(settings, params)
    return load_huawei_live(params)


def _load_source_records_from_run(settings, params: dict[str, Any]) -> list[dict[str, Any]] | None:
    run_id = params.get("resume_from_run_id") or params.get("source_run_id")
    if not run_id:
        return None
    path = settings.output_dir / "shadow_runs" / str(run_id) / "threats" / "huawei_source_records.json"
    if not path.exists():
        return None
    return _read_source_records(path)


def _load_source_records_from_path(params: dict[str, Any]) -> list[dict[str, Any]] | None:
    raw_path = params.get("source_records_path")
    if not raw_path:
        return None
    path = Path(str(raw_path))
    if not path.exists():
        return None
    return _read_source_records(path)


def _read_source_records(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    records = data.get("records") if isinstance(data, dict) else data
    return [record for record in records or [] if isinstance(record, dict)]


def _source_cache_path(settings, params: dict[str, Any]) -> Path:
    signature = json.dumps(_cache_signature_payload(params), ensure_ascii=False, sort_keys=True, default=str)
    digest = hashlib.sha256(signature.encode("utf-8")).hexdigest()[:16]
    return settings.output_dir / "cache" / "threats" / "huawei_sources" / f"{digest}.json"


def _source_record_cache_path(settings, source: str, params: dict[str, Any]) -> Path:
    signature = json.dumps(_cache_signature_payload({**params, "source": source}), ensure_ascii=False, sort_keys=True, default=str)
    digest = hashlib.sha256(signature.encode("utf-8")).hexdigest()[:16]
    return settings.output_dir / "cache" / "threats" / "huawei_sources" / source / f"{digest}.json"


def _cache_signature_payload(params: dict[str, Any]) -> dict[str, Any]:
    excluded = {"reset", "refresh_source_cache", "refresh_sources", "use_source_cache", "sources", "resume_from_run_id", "source_run_id", "source_records_path"}
    return {key: value for key, value in sorted(params.items()) if key not in excluded}


def load_huawei_live(params: dict[str, Any]) -> list[dict[str, Any]]:
    registry = SourceRegistry()
    records = []
    requested = _requested_sources(params)
    if "repos" in requested:
        records.extend(_collect_repo_records(registry, params))
    records.extend(_collect_live_assets(registry, params, requested_sources=requested))
    return records


def _load_huawei_sources_with_source_cache(settings, params: dict[str, Any]) -> list[dict[str, Any]]:
    registry = SourceRegistry()
    requested = _requested_sources(params)
    refresh_sources = _as_source_set(params.get("refresh_sources"))
    refresh_all = bool(params.get("refresh_source_cache", False))
    records = []
    collectors = {
        "repos": lambda: _collect_repo_records(registry, params),
        "firmware": lambda: _collect_firmware_assets(registry, params),
        "ascendhub": lambda: _collect_ascendhub_assets(registry, params),
        "mirrors": lambda: _collect_single_asset_source(registry, "mirrors", "huawei_mirror", {"catalog": params.get("mirror_catalog", ""), "timeout_seconds": params.get("timeout_seconds", 20)}),
        "openx_huawei": lambda: _collect_openx_huawei_assets(registry, params),
    }
    for source in ["repos", "firmware", "ascendhub", "mirrors", "openx_huawei"]:
        if source not in requested:
            continue
        cache_path = _source_record_cache_path(settings, source, params)
        if not refresh_all and source not in refresh_sources and cache_path.exists():
            records.extend(_read_source_records(cache_path))
            continue
        record = collectors[source]()
        source_records = record if isinstance(record, list) else [record]
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps({"records": source_records, "params": _cache_signature_payload(params)}, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        records.extend(source_records)
    return records


def _collect_repo_record(registry: SourceRegistry, params: dict[str, Any]) -> dict[str, Any]:
    return _collect_repo_records(registry, params)[0]


def _collect_repo_records(registry: SourceRegistry, params: dict[str, Any]) -> list[dict[str, Any]]:
    repos = _collect_live_repos(registry, params)
    repos, org_security_materials = _enrich_security_repos(registry, repos, params)
    repos = _enrich_project_issues(registry, repos, params)
    records = [{"source": "repos", "path": "connector:repos", "exists": True, "items": repos, "raw": {"projects": repos, "mode": "live"}, "mode": "live"}]
    if org_security_materials:
        records.append({"source": "org_security_materials", "path": "connector:security_repos", "exists": True, "items": org_security_materials, "raw": {"mode": "live", "orgs": sorted({str(item.get("org") or "") for item in org_security_materials if item.get("org")})}, "mode": "live"})
    return records


def _requested_sources(params: dict[str, Any]) -> set[str]:
    requested = _as_source_set(params.get("sources")) or {"repos", "firmware", "ascendhub", "mirrors", "openx_huawei"}
    if not params.get("include_assets", True):
        requested -= {"firmware", "ascendhub", "mirrors", "openx_huawei"}
    return requested


def _as_source_set(value: Any) -> set[str]:
    if not value:
        return set()
    if isinstance(value, str):
        return {item.strip() for item in value.split(",") if item.strip()}
    if isinstance(value, list):
        return {str(item).strip() for item in value if str(item).strip()}
    return set()


def _collect_live_repos(registry: SourceRegistry, params: dict[str, Any]) -> list[dict[str, Any]]:
    orgs = params.get("orgs") or DEFAULT_LIVE_ORGS
    page_limit = int(params.get("page_limit", 3 if _full_scan(params) else 1))
    per_page = int(params.get("per_page", 100 if _full_scan(params) else 50))
    max_workers = int(params.get("max_workers", 6 if _full_scan(params) else 4))
    chunks = bounded_map(orgs, lambda entry: _collect_org_repos(registry, entry, params, page_limit=page_limit, per_page=per_page), max_workers=max_workers)
    return [repo for chunk in chunks for repo in chunk]


def _collect_org_repos(registry: SourceRegistry, entry: Any, params: dict[str, Any], *, page_limit: int, per_page: int) -> list[dict[str, Any]]:
    repos: list[dict[str, Any]] = []
    if isinstance(entry, str):
        platform, org = _split_platform_org(entry)
    else:
        platform = str(entry.get("platform") or "gitcode")
        org = str(entry.get("org") or "")
    connector = registry.get(platform)
    for page in range(1, page_limit + 1):
        result = connector.fetch(SourceFetchRequest(source_name=f"{platform}:{org}:repos", params={"resource": "repos", "org": org, "page": page, "per_page": per_page, "timeout_seconds": params.get("timeout_seconds", 15)}))
        if result.errors:
            break
        batch = [_normalize_repo_item(item, org=org, platform=platform) for item in result.items]
        repos.extend(batch)
        if len(batch) < per_page:
            break
    return repos


def _enrich_project_issues(registry: SourceRegistry, repos: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    if not repos or not params.get("fetch_project_issues", True):
        return repos
    star_threshold = int(params.get("project_issue_star_threshold", 10))
    issue_pages = int(params.get("project_issue_pages", 2 if _full_scan(params) else 1))
    pr_pages = int(params.get("project_pr_pages", 1 if _full_scan(params) else 0))
    repo_limit = int(params.get("project_issue_repo_limit", 300 if _full_scan(params) else 30))
    candidates = [repo for repo in repos if int(repo.get("star_count") or 0) >= star_threshold and not repo.get("is_security_repo")]
    candidates.sort(key=lambda item: (-(int(item.get("star_count") or 0)), str(item.get("org") or ""), str(item.get("name") or "")))
    def enrich_repo(repo: dict[str, Any]) -> dict[str, Any]:
        platform = str(repo.get("platform") or _platform_from_url(repo.get("url") or ""))
        owner = str(repo.get("org") or "")
        repo_name = str(repo.get("name") or "")
        if not platform or not owner or not repo_name:
            return repo
        connector = registry.get(platform)
        repo["issues"] = _fetch_paginated_repo_items(connector, platform, owner, repo_name, resource="issues", pages=issue_pages, timeout=int(params.get("timeout_seconds", 15)))
        if pr_pages:
            repo["pull_requests"] = _fetch_paginated_repo_items(connector, platform, owner, repo_name, resource="pull_requests", pages=pr_pages, timeout=int(params.get("timeout_seconds", 15)))
        repo["project_issue_scanned"] = True
        return repo

    max_workers = int(params.get("issue_max_workers", params.get("max_workers", 6 if _full_scan(params) else 4)))
    bounded_map(candidates[:repo_limit], enrich_repo, max_workers=max_workers)
    return repos


def _fetch_paginated_repo_items(connector, platform: str, owner: str, repo_name: str, *, resource: str, pages: int, timeout: int) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for page in range(1, pages + 1):
        result = connector.fetch(SourceFetchRequest(source_name=f"{platform}:{owner}/{repo_name}:{resource}", params={"resource": resource, "owner": owner, "repo": repo_name, "page": page, "per_page": 100, "timeout_seconds": timeout}))
        if result.errors or not result.items:
            break
        items.extend(result.items)
        if len(result.items) < 100:
            break
    return items


def _enrich_security_repos(registry: SourceRegistry, repos: list[dict[str, Any]], params: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not repos or not params.get("fetch_security_details", True):
        return repos, []
    grouped = group_projects_by_org(repos)
    security = discover_security_repos(grouped)
    issue_pages = int(params.get("security_issue_pages", 20 if _full_scan(params) else 1))
    pr_pages = int(params.get("security_pr_pages", 1 if _full_scan(params) else 0))
    max_files = int(params.get("security_file_limit", 200 if _full_scan(params) else 3))
    max_security_repos = int(params.get("security_repo_limit", 50 if _full_scan(params) else 2))
    max_content_dirs = int(params.get("security_content_dir_limit", 200 if _full_scan(params) else 20))
    by_key = {(repo.get("platform"), repo.get("org"), repo.get("name")): repo for repo in repos}
    org_security_materials: list[dict[str, Any]] = []
    for org, sec_data in security.items():
        for sec_repo in (sec_data.get("security_repos") or [])[:max_security_repos]:
            platform = sec_repo.get("platform") or _platform_from_url(sec_repo.get("url") or "")
            owner = sec_repo.get("org") or org
            repo_name = sec_repo.get("name") or ""
            connector = registry.get(platform) if platform else None
            if not connector or not repo_name:
                continue
            issues = []
            for page in range(1, issue_pages + 1):
                result = connector.fetch(SourceFetchRequest(source_name=f"{platform}:{owner}/{repo_name}:issues", params={"resource": "issues", "owner": owner, "repo": repo_name, "page": page, "per_page": 100, "timeout_seconds": params.get("timeout_seconds", 15)}))
                if result.errors or not result.items:
                    break
                issues.extend(result.items)
                if len(result.items) < 100:
                    break
            org_security_materials.extend(_security_issue_materials(issues, platform=platform, org=owner, repo=repo_name))
            pull_requests = []
            for page in range(1, pr_pages + 1):
                result = connector.fetch(SourceFetchRequest(source_name=f"{platform}:{owner}/{repo_name}:prs", params={"resource": "pull_requests", "owner": owner, "repo": repo_name, "page": page, "per_page": 100, "timeout_seconds": params.get("timeout_seconds", 15)}))
                if result.errors or not result.items:
                    break
                pull_requests.extend(result.items)
                if len(result.items) < 100:
                    break
            org_security_materials.extend(_security_pr_materials(pull_requests, platform=platform, org=owner, repo=repo_name))
            security_files = []
            if params.get("parse_security_source_repos", False) or not _is_security_source_code_repo(repo_name):
                security_files = _fetch_security_files(connector, platform, owner, repo_name, max_files=max_files, max_dirs=max_content_dirs)
                org_security_materials.extend(_security_file_materials(security_files, platform=platform, org=owner, repo=repo_name))
            key = (platform, owner, repo_name)
            target = by_key.get(key) or sec_repo
            target["issues"] = issues
            target["pull_requests"] = pull_requests
            target["security_files"] = security_files
            target["is_security_repo"] = True
            target["org_security_repo_count"] = len(sec_data.get("security_repos") or [])
    return repos, org_security_materials


def _security_issue_materials(issues: list[dict[str, Any]], *, platform: str, org: str, repo: str) -> list[dict[str, Any]]:
    return [_security_material(item, material_type="security_repo_issue", platform=platform, org=org, repo=repo) for item in issues]


def _security_pr_materials(pull_requests: list[dict[str, Any]], *, platform: str, org: str, repo: str) -> list[dict[str, Any]]:
    return [_security_material(item, material_type="security_repo_pr", platform=platform, org=org, repo=repo) for item in pull_requests]


def _security_file_materials(files: list[dict[str, Any]], *, platform: str, org: str, repo: str) -> list[dict[str, Any]]:
    return [_security_material(item, material_type="security_repo_file", platform=platform, org=org, repo=repo) for item in files]


def _security_material(item: dict[str, Any], *, material_type: str, platform: str, org: str, repo: str) -> dict[str, Any]:
    return {**item, "material_type": material_type, "platform": platform, "org": org, "repo": repo}


def _is_security_source_code_repo(repo_name: str) -> bool:
    return str(repo_name or "").lower() in SECURITY_SOURCE_CODE_REPO_NAMES


def _fetch_security_files(connector, platform: str, owner: str, repo_name: str, *, max_files: int, max_dirs: int) -> list[dict[str, Any]]:
    candidates = _discover_security_file_paths(connector, platform, owner, repo_name, max_files=max_files, max_dirs=max_dirs)
    files = []
    for path in candidates[:max_files]:
        result = connector.fetch(SourceFetchRequest(source_name=f"{platform}:{owner}/{repo_name}:file", params={"resource": "file", "owner": owner, "repo": repo_name, "path": path, "timeout_seconds": 15}))
        if result.errors:
            continue
        files.append({"path": path, "content": result.raw_text, "source_url": f"{_web_base(platform)}/{owner}/{repo_name}/blob/master/{path}"})
    return files


def _discover_security_file_paths(connector, platform: str, owner: str, repo_name: str, *, max_files: int, max_dirs: int) -> list[str]:
    candidates: list[str] = []
    visited: set[str] = set()
    queue: list[tuple[str, int, bool]] = [("", 0, False)]
    while queue and len(visited) < max_dirs and len(candidates) < max_files:
        path, depth, under_security = queue.pop(0)
        if path in visited or depth > 4:
            continue
        visited.add(path)
        contents = connector.fetch(SourceFetchRequest(source_name=f"{platform}:{owner}/{repo_name}:contents:{path or 'root'}", params={"resource": "contents", "owner": owner, "repo": repo_name, "path": path, "timeout_seconds": 15}))
        if contents.errors:
            continue
        for item in contents.items:
            item_path = item.get("path") or item.get("name") or ""
            name = item.get("name") or item_path.rsplit("/", 1)[-1]
            lowered = item_path.lower()
            item_type = item.get("type") or ""
            if item_type in {"dir", "tree"}:
                security_dir = under_security or _is_security_path(name) or _is_security_path(item_path) or _is_year_dir(name)
                if security_dir or (depth < 2 and not under_security):
                    queue.append((item_path, depth + 1, security_dir))
                continue
            if not under_security and not _is_security_path(item_path):
                continue
            if lowered.endswith(SECURITY_FILE_SUFFIXES):
                candidates.append(item_path)
                if len(candidates) >= max_files:
                    break
    return candidates


def _is_security_path(value: str) -> bool:
    lowered = (value or "").lower()
    return any(term.lower() in lowered for term in [*SECURITY_FILE_TERMS, *CVE_DIR_TERMS])


def _is_year_dir(value: str) -> bool:
    return bool(value and value.isdigit() and len(value) == 4)


def _collect_live_assets(registry: SourceRegistry, params: dict[str, Any], requested_sources: set[str] | None = None) -> list[dict[str, Any]]:
    if not params.get("include_assets", True):
        return []
    requested = requested_sources or _requested_sources(params)
    collectors = []
    if "firmware" in requested:
        collectors.append(lambda: _collect_firmware_assets(registry, params))
    if "ascendhub" in requested:
        collectors.append(lambda: _collect_ascendhub_assets(registry, params))
    if "mirrors" in requested:
        collectors.append(lambda: _collect_single_asset_source(registry, "mirrors", "huawei_mirror", {"catalog": params.get("mirror_catalog", ""), "timeout_seconds": params.get("timeout_seconds", 20)}))
    if "openx_huawei" in requested:
        collectors.append(lambda: _collect_openx_huawei_assets(registry, params))
    return bounded_map(collectors, lambda collector: collector(), max_workers=int(params.get("asset_max_workers", 4 if _full_scan(params) else 2)))


def _collect_firmware_assets(registry: SourceRegistry, params: dict[str, Any]) -> dict[str, Any]:
    connector = registry.get("hiascend")
    products = connector.fetch(SourceFetchRequest(source_name="hiascend:firmware_products", params={"endpoint": "softwareCenter/queryResourceProductList", "lang": "zh", "type": "community", "timeout_seconds": params.get("timeout_seconds", 20)}))
    items = []
    errors = list(products.errors)
    product_limit = int(params.get("firmware_product_limit", 20 if _full_scan(params) else 2))
    model_limit = int(params.get("firmware_model_limit", 200 if _full_scan(params) else 5))
    cann_limit = int(params.get("firmware_cann_limit", 10 if _full_scan(params) else 1))
    package_limit = int(params.get("firmware_package_limit", 50 if _full_scan(params) else 3))
    resource_limit = int(params.get("firmware_resource_limit", 200 if _full_scan(params) else 20))
    for product in products.items[:product_limit]:
        product_id = product.get("productId") or product.get("id")
        if not product_id:
            items.append({**product, "source_type": "firmware_product"})
            continue
        models = connector.fetch(SourceFetchRequest(source_name=f"hiascend:firmware_models:{product_id}", params={"endpoint": "softwareCenter/queryProductModelList", "lang": "zh", "type": "community", "productId": product_id, "timeout_seconds": params.get("timeout_seconds", 20)}))
        errors.extend(models.errors)
        if not models.items:
            items.append({**product, "source_type": "firmware_product"})
            continue
        for model in models.items[:model_limit]:
            model_id = model.get("modelId") or model.get("id")
            base_model = {**model, "productId": product_id, "productName": product.get("productName"), "source_type": "firmware_model"}
            items.append(base_model)
            if not model_id:
                continue
            cann_versions = connector.fetch(SourceFetchRequest(source_name=f"hiascend:cann:{model_id}", params={"endpoint": "softwareCenter/getCannVersion", "lang": "zh", "type": "community", "modelId": model_id, "timeout_seconds": params.get("timeout_seconds", 20)}))
            errors.extend(cann_versions.errors)
            for cann in cann_versions.items[:cann_limit]:
                cann_id = cann.get("cannId") or cann.get("id")
                cann_version = cann.get("cannVersion") or cann.get("version") or ""
                items.append({**base_model, **cann, "cannId": cann_id, "cannVersion": cann_version, "source_type": "firmware_cann"})
                if not cann_id:
                    continue
                packages = connector.fetch(SourceFetchRequest(source_name=f"hiascend:firmware_packages:{model_id}:{cann_id}", params={"endpoint": "softwareCenter/getFirmwareVersion", "lang": "zh", "type": "community", "modelId": model_id, "cannId": cann_id, "timeout_seconds": params.get("timeout_seconds", 20)}))
                errors.extend(packages.errors)
                for package in packages.items[:package_limit]:
                    firmware_version = package if isinstance(package, str) else package.get("firmwareName") or package.get("version") or package.get("name") or ""
                    package_payload = package if isinstance(package, dict) else {"firmwareVersion": firmware_version}
                    items.append({**base_model, **package_payload, "cannId": cann_id, "cannVersion": cann_version, "firmwareVersion": firmware_version, "source_type": "firmware_package"})
                    if not firmware_version:
                        continue
                    resources = connector.fetch(SourceFetchRequest(source_name=f"hiascend:firmware_resources:{model_id}:{firmware_version}", params={"endpoint": "softwareCenter/queryResourceCenterList", "lang": "zh", "type": "community", "modelId": model_id, "version": firmware_version, "productType": "", "cpuArchitecture": "", "softwareType": "", "timeout_seconds": params.get("timeout_seconds", 20)}))
                    errors.extend(resources.errors)
                    for resource in resources.items[:resource_limit]:
                        items.append({**base_model, **resource, "cannId": cann_id, "cannVersion": cann_version, "firmwareVersion": firmware_version, "productTypeFilter": "", "cpuArchitectureFilter": "", "softwareTypeFilter": "", "source_type": "firmware_resource"})
    if params.get("include_commercial_firmware", _full_scan(params)):
        commercial_items, commercial_errors = _collect_commercial_firmware(connector, params)
        items.extend(commercial_items)
        errors.extend(commercial_errors)
    return {"source": "firmware", "path": "connector:hiascend", "exists": not bool(errors), "items": items, "raw": {"metadata": products.metadata, "errors": errors, "mode": "live"}, "mode": "live"}


def _collect_commercial_firmware(connector, params: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    products = connector.fetch(SourceFetchRequest(source_name="hiascend:commercial_products", params={"endpoint": "softwareCenter/queryResourceProductList", "lang": "zh", "type": "business", "timeout_seconds": params.get("timeout_seconds", 20)}))
    items: list[dict[str, Any]] = []
    errors = list(products.errors)
    product_limit = int(params.get("commercial_product_limit", 20 if _full_scan(params) else 2))
    model_limit = int(params.get("commercial_model_limit", 200 if _full_scan(params) else 5))
    page_size = int(params.get("commercial_page_size", 15))
    page_limit = int(params.get("commercial_page_limit", 20 if _full_scan(params) else 1))
    for product in products.items[:product_limit]:
        product_id = product.get("productId") or product.get("id")
        if not product_id:
            continue
        models = connector.fetch(SourceFetchRequest(source_name=f"hiascend:commercial_models:{product_id}", params={"endpoint": "softwareCenter/queryProductModelList", "lang": "zh", "type": "business", "productId": product_id, "timeout_seconds": params.get("timeout_seconds", 20)}))
        errors.extend(models.errors)
        for model in models.items[:model_limit]:
            model_id = model.get("modelId") or model.get("id")
            if not model_id:
                continue
            for page in range(1, page_limit + 1):
                result = connector.fetch(SourceFetchRequest(source_name=f"hiascend:commercial_list:{model_id}:{page}", params={"endpoint": "firmware/commercial/list", "lang": "zh", "modelId": model_id, "pageNo": page, "pageSize": page_size, "timeout_seconds": params.get("timeout_seconds", 20)}))
                errors.extend(result.errors)
                for item in result.items:
                    items.append({**model, **item, "productId": product_id, "productName": product.get("productName"), "source_type": "firmware_commercial"})
                if len(result.items) < page_size:
                    break
    return items, errors


def _collect_ascendhub_assets(registry: SourceRegistry, params: dict[str, Any]) -> dict[str, Any]:
    connector = registry.get("hiascend")
    targets = params.get("ascendhub_targets") or DEFAULT_ASCENDHUB_TARGETS
    limit = int(params.get("ascendhub_limit", len(targets) if _full_scan(params) else min(2, len(targets))))
    items = []
    errors = []
    for target in targets[:limit]:
        hub_id = target.get("hub_id") or target.get("id")
        if not hub_id:
            continue
        detail = connector.fetch(SourceFetchRequest(source_name=f"hiascend:ascendhub:{hub_id}", params={"endpoint": "ascendHub/repositories/detail", "id": hub_id, "lang": "zh", "timeout_seconds": params.get("timeout_seconds", 20)}))
        errors.extend(detail.errors)
        if detail.items:
            for item in detail.items:
                items.append({**item, "hub_id": hub_id, "name": item.get("name") or target.get("name"), "source_type": "ascendhub"})
        tag_pages = int(params.get("ascendhub_tag_pages", 2 if _full_scan(params) else 1))
        tag_page_size = int(params.get("ascendhub_tag_page_size", 50 if _full_scan(params) else 10))
        for page in range(1, tag_pages + 1):
            tags = connector.fetch(SourceFetchRequest(source_name=f"hiascend:ascendhub_tags:{hub_id}:{page}", params={"endpoint": "ascendHub/repositories/tags", "id": hub_id, "lang": "zh", "pageNo": page, "pageSize": tag_page_size, "timeout_seconds": params.get("timeout_seconds", 20)}))
            errors.extend(tags.errors)
            for tag in tags.items:
                items.append({**tag, "hub_id": hub_id, "hub_name": target.get("name"), "source_type": "ascendhub_tag"})
            if len(tags.items) < tag_page_size:
                break
    return {"source": "ascendhub", "path": "connector:hiascend", "exists": not bool(errors), "items": items, "raw": {"errors": errors, "mode": "live"}, "mode": "live"}


def _collect_single_asset_source(registry: SourceRegistry, source: str, connector_name: str, connector_params: dict[str, Any]) -> dict[str, Any]:
    connector = registry.get(connector_name)
    result = connector.fetch(SourceFetchRequest(source_name=f"{connector_name}:{source}", params=connector_params))
    return {"source": source, "path": f"connector:{connector_name}", "exists": not bool(result.errors), "items": result.items, "raw": {"metadata": result.metadata, "errors": result.errors, "mode": "live"}, "mode": "live"}


def _collect_openx_huawei_assets(registry: SourceRegistry, params: dict[str, Any]) -> dict[str, Any]:
    connector = registry.get("openx_huawei")
    root = connector.fetch(SourceFetchRequest(source_name="openx_huawei:root", params={"timeout_seconds": params.get("timeout_seconds", 20)}))
    errors = list(root.errors)
    items: list[dict[str, Any]] = []
    max_depth = int(params.get("openx_depth", 4 if _full_scan(params) else 1))
    max_dirs = int(params.get("openx_dir_limit", 200 if _full_scan(params) else 8))
    max_files = int(params.get("openx_file_limit", 500 if _full_scan(params) else 30))
    queue = [(item, 0, item.get("name") or "") for item in root.items if item.get("is_dir")]
    visited = 0
    while queue and visited < max_dirs and len(items) < max_files:
        node, depth, category = queue.pop(0)
        if depth >= max_depth:
            continue
        visited += 1
        result = connector.fetch(SourceFetchRequest(source_name=f"openx_huawei:{node.get('url')}", params={"url": node.get("url"), "timeout_seconds": params.get("timeout_seconds", 20)}))
        errors.extend(result.errors)
        for child in result.items:
            child = {**child, "category": category, "source_type": "openx_huawei"}
            if child.get("is_dir"):
                queue.append((child, depth + 1, category))
            else:
                items.append(child)
                if len(items) >= max_files:
                    break
    return {"source": "openx_huawei", "path": "connector:openx_huawei", "exists": not bool(errors), "items": items, "raw": {"metadata": root.metadata, "errors": errors, "mode": "live", "visited_dirs": visited}, "mode": "live"}


def _full_scan(params: dict[str, Any]) -> bool:
    return str(params.get("scan_profile") or "").lower() in {"full", "full_scan", "deep"} or bool(params.get("full_scan"))


def _split_platform_org(value: str) -> tuple[str, str]:
    if ":" in value:
        platform, org = value.split(":", 1)
        return platform, org
    return "gitcode", value


def _normalize_repo_item(item: dict[str, Any], *, org: str, platform: str) -> dict[str, Any]:
    owner = item.get("namespace", {}).get("path") if isinstance(item.get("namespace"), dict) else ""
    repo_org = item.get("org") or owner or org
    name = item.get("name") or item.get("path") or item.get("repo") or ""
    url = item.get("html_url") or item.get("web_url") or item.get("url") or (f"{_web_base(platform)}/{repo_org}/{name}" if name else "")
    return {"name": name, "url": url, "description": item.get("description") or item.get("desc") or "", "star_count": item.get("stargazers_count") or item.get("stars") or item.get("star_count") or 0, "org": repo_org, "platform": platform, "raw": item}


def _platform_from_url(url: str) -> str:
    if "atomgit.com" in (url or ""):
        return "atomgit"
    return "gitcode"


def _web_base(platform: str) -> str:
    return "https://atomgit.com" if platform == "atomgit" else "https://gitcode.com"
