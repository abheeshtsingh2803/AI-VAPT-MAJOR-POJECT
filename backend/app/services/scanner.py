import aiohttp
from bs4 import BeautifulSoup

async def scan_web_application(url: str):
    vulnerabilities = []

    async with aiohttp.ClientSession() as session:
        async with session.get(url) as res:
            html = await res.text()
            soup = BeautifulSoup(html, "html.parser")

            if soup.find("form"):
                vulnerabilities.append({
                    "type": "XSS",
                    "severity": "High",
                    "title": "Potential XSS",
                    "description": "Form without sanitization",
                    "location": url,
                    "recommendation": "Validate inputs",
                    "cvss_score": 7.5
                })

    return vulnerabilities
