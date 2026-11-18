import asyncio
import difflib
import hashlib
import os
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
import httpx
import trafilatura
from curl_cffi.requests import AsyncSession

CDX_API = "https://web.archive.org/cdx/search/cdx"
DIFFS_DIR = Path("diffs")

ARCHIVE_HEADERS = {
    "User-Agent": "ArchiveDiffChecker/1.0 (contact: your-email@example.com)"
}

# Terminal Colors (STDOUT only)
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"


def extract_clean_lines(html: str) -> list[str]:
    """Extract clean, paragraph-separated text lines for meaningful line-by-line diffs."""
    text = trafilatura.extract(html) or ""
    return [line.strip() for line in text.splitlines() if line.strip()]


def lines_hash(lines: list[str]) -> str:
    normalized = "\n".join(lines).lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def url_folder_name(url: str) -> str:
    """Turn a URL into a clean, collision-safe folder name under diffs/."""
    parsed = urlparse(url)
    raw = f"{parsed.netloc}{parsed.path}".strip("/")
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", raw)[:100]
    short_hash = hashlib.md5(url.encode()).hexdigest()[:6]
    return f"{slug}_{short_hash}"


def format_date_str(ts: str) -> str:
    """Convert a 14-digit Wayback timestamp (YYYYMMDDHHMMSS) or 'live' to YYYYMMDD."""
    if ts == "live":
        return datetime.now().strftime("%Y%m%d")
    return ts[:8]


def generate_git_diff(
    old_lines: list[str],
    new_lines: list[str],
    virtual_path: str,
    old_label: str,
    new_label: str,
) -> str:
    """Generate a standard plain-text Git unified diff."""
    old_sha = lines_hash(old_lines)[:7]
    new_sha = lines_hash(new_lines)[:7]

    header = [
        f"diff --git a/{virtual_path} b/{virtual_path}",
        f"index {old_sha}..{new_sha} 100644",
    ]

    hunks = list(
        difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=f"a/{virtual_path} ({old_label})",
            tofile=f"b/{virtual_path} ({new_label})",
            lineterm="",
        )
    )

    return "\n".join(header + hunks) + "\n"


async def fetch_archive_with_retry(
    client: httpx.AsyncClient, url: str, params=None, retries: int = 3
) -> str:
    for attempt in range(retries):
        try:
            resp = await client.get(url, params=params, follow_redirects=True, timeout=30.0)
            if resp.status_code in (429, 502, 503, 504):
                await asyncio.sleep(2 ** attempt + 1)
                continue
            resp.raise_for_status()
            return resp.text
        except (httpx.RemoteProtocolError, httpx.ReadTimeout, httpx.ConnectError):
            if attempt == retries - 1:
                raise
            await asyncio.sleep(2 ** attempt + 1)
    raise RuntimeError(f"Archive fetch failed after {retries} retries: {url}")


async def fetch_live_with_retry(
    session: AsyncSession, url: str, retries: int = 3
) -> str:
    """Fetch live URL using Chrome TLS impersonation to bypass 403 WAF blocks."""
    for attempt in range(retries):
        try:
            resp = await session.get(url, allow_redirects=True, timeout=30)
            if resp.status_code in (403, 429, 502, 503, 504):
                if attempt < retries - 1:
                    await asyncio.sleep(2 ** attempt + 1)
                    continue
            resp.raise_for_status()
            return resp.text
        except Exception:
            if attempt == retries - 1:
                raise
            await asyncio.sleep(2 ** attempt + 1)
    raise RuntimeError(f"Live fetch failed after {retries} retries: {url}")


async def check_url(
    archive_client: httpx.AsyncClient,
    live_session: AsyncSession,
    url: str,
    sem: asyncio.Semaphore,
    max_snapshots: int | None = None,
) -> dict:
    async with sem:
        try:
            cdx_params = {
                "url": url,
                "output": "json",
                "fl": "timestamp,original,digest",
                "filter": "statuscode:200",
                "collapse": "digest",
            }
            cdx_resp = await archive_client.get(CDX_API, params=cdx_params, timeout=30.0)
            cdx_resp.raise_for_status()
            rows = cdx_resp.json()
        except Exception as e:
            return {"url": url, "status": "error", "detail": f"CDX error: {e}"}

        if len(rows) <= 1:
            return {"url": url, "status": "no_archive"}

        snapshots = rows[1:]
        if max_snapshots and len(snapshots) > max_snapshots:
            snapshots = [snapshots[0]] + snapshots[-(max_snapshots - 1) :]

        try:
            live_html = await fetch_live_with_retry(live_session, url)
        except Exception as e:
            return {"url": url, "status": "error", "detail": f"Live fetch error: {e}"}

        versions: list[tuple[str, str, list[str]]] = []
        for ts, _, _ in snapshots:
            raw_archive_url = f"https://web.archive.org/web/{ts}id_/{url}"
            try:
                arch_html = await fetch_archive_with_retry(archive_client, raw_archive_url)
                lines = extract_clean_lines(arch_html)
                if not lines:
                    continue
                if not versions or lines_hash(lines) != lines_hash(versions[-1][2]):
                    versions.append((f"archive:{ts}", ts, lines))
            except Exception:
                continue

        live_lines = extract_clean_lines(live_html)
        if live_lines and (not versions or lines_hash(live_lines) != lines_hash(versions[-1][2])):
            versions.append(("live", "live", live_lines))

        if len(versions) <= 1:
            oldest_ts = snapshots[0][0]
            return {
                "url": url,
                "status": "unchanged",
                "archive_link": f"https://web.archive.org/web/{oldest_ts}/{url}",
            }

        folder_name = url_folder_name(url)
        source_dir = DIFFS_DIR / folder_name
        source_dir.mkdir(parents=True, exist_ok=True)

        written_files: list[str] = []
        used_filenames: dict[str, int] = {}

        for i in range(len(versions) - 1):
            old_label, old_ts, old_lines = versions[i]
            new_label, new_ts, new_lines = versions[i + 1]

            old_date = format_date_str(old_ts)
            new_date = format_date_str(new_ts)
            base_name = f"{old_date}_{new_date}"

            count = used_filenames.get(base_name, 0) + 1
            used_filenames[base_name] = count
            filename = f"{base_name}.diff" if count == 1 else f"{base_name}-{count}.diff"

            diff_content = generate_git_diff(
                old_lines=old_lines,
                new_lines=new_lines,
                virtual_path=f"{folder_name}.txt",
                old_label=old_label,
                new_label=new_label,
            )
            diff_path = source_dir / filename
            diff_path.write_text(diff_content, encoding="utf-8")
            written_files.append(str(diff_path))

        oldest_ts = versions[0][1]
        return {
            "url": url,
            "status": "changed",
            "archive_link": f"https://web.archive.org/web/{oldest_ts}/{url}",
            "diff_dir": str(source_dir),
            "diff_count": len(written_files),
        }


async def process_urls(
    urls: list[str],
    max_concurrency: int = 2,
    max_snapshots: int | None = None,
):
    sem = asyncio.Semaphore(max_concurrency)
    limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)

    changed: list[dict] = []
    unchanged: list[dict] = []
    other: list[dict] = []

    print(f"{DIM}Checking {len(urls)} URL(s)...{RESET}\n")

    async with (
        httpx.AsyncClient(headers=ARCHIVE_HEADERS, limits=limits) as archive_client,
        AsyncSession(impersonate="chrome") as live_session,
    ):
        tasks = [
            check_url(archive_client, live_session, u, sem, max_snapshots=max_snapshots)
            for u in urls
        ]
        for coro in asyncio.as_completed(tasks):
            res = await coro
            status = res["status"]
            if status == "changed":
                changed.append(res)
                print(
                    f"{GREEN}● CHANGED{RESET}   {res['url']} "
                    f"{DIM}({res['diff_count']} diff(s) -> {res['diff_dir']}/){RESET}"
                )
            elif status == "unchanged":
                unchanged.append(res)
                print(f"{DIM}○ UNCHANGED {res['url']}{RESET}")
            else:
                other.append(res)
                detail = res.get("detail", "No archive found")
                print(f"{YELLOW}▲ SKIPPED{RESET}   {res['url']} {DIM}({detail}){RESET}")

    print(f"\n{BOLD}{GREEN}Changed urls:{RESET}\n")
    if changed:
        for item in changed:
            print(f"{CYAN}{item['archive_link']}{RESET} {BOLD}->{RESET} {GREEN}{item['url']}{RESET}")
    else:
        print(f"{DIM}(none){RESET}")

    print(f"\n{BOLD}{YELLOW}Unchanged urls:{RESET}\n")
    if unchanged:
        for item in unchanged:
            print(f"{DIM}{item['archive_link']}{RESET}")
    else:
        print(f"{DIM}(none){RESET}")

    if other:
        print(f"\n{BOLD}{RED}Skipped / Errors:{RESET}\n")
        for item in other:
            detail = item.get("detail", "no archive")
            print(f"{RED}{item['url']}{RESET} {DIM}({detail}){RESET}")


if __name__ == "__main__":
    if os.path.exists("urls.txt"):
        with open("urls.txt") as f:
            url_list = [line.strip() for line in f if line.strip()]
    else:
        url_list = ["https://www.huit.harvard.edu/ai/guidelines"]

    asyncio.run(process_urls(url_list, max_concurrency=2, max_snapshots=None))