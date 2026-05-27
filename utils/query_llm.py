import os
from typing import Dict, List

from zhipuai import ZhipuAI


def get_glm_response(
    messages: List[Dict[str, str]],
    model: str = "glm-4-flash-250414",
    temperature: float = 0.2,
) -> str:
    """
    Call Zhipu GLM model.

    API key is read from environment variable:
        ZHIPUAI_API_KEY
    """
    api_key = os.environ.get("ZHIPUAI_API_KEY", "").strip()

    if not api_key:
        raise RuntimeError(
            "ZHIPUAI_API_KEY is not set. "
            "Please run: export ZHIPUAI_API_KEY='your_key'"
        )

    client = ZhipuAI(api_key=api_key)

    resp = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=temperature,
    )

    return resp.choices[0].message.content
