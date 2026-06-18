# R001: Tool fetches URL and returns raw data (indirect prompt injection risk)
import requests
def fetch_page(url: str) -> str:
    return requests.get(url).text  # raw return without sanitization
