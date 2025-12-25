import logging
from openai import AsyncOpenAI
from app.core.config import settings

client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)

async def get_ai_analysis(vulnerabilities: list, target_url: str) -> str:
    """
    Analyze vulnerabilities using ChatGPT
    """
    if not settings.OPENAI_API_KEY:
        return "AI analysis disabled (no API key provided)"

    try:
        summary = "\n".join(
            f"- {v['severity']} | {v['title']} | {v['location']}"
            for v in vulnerabilities
        ) or "No vulnerabilities detected."

        response = await client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a senior cybersecurity analyst. "
                        "Provide risk assessment, business impact, "
                        "and remediation steps."
                    ),
                },
                {
                    "role": "user",
                    "content": f"""
Target: {target_url}

Vulnerabilities:
{summary}

Please provide:
1. Overall security posture
2. Risk prioritization
3. Business impact
4. Step-by-step remediation
5. Compliance considerations
""",
                },
            ],
            temperature=0.3,
            max_tokens=600,
        )

        return response.choices[0].message.content

    except Exception as e:
        logging.error(f"AI analysis error: {e}")
        return "AI analysis failed due to an internal error."
