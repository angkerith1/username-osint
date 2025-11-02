"""Enhanced username OSINT scanner."""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import requests
from colorama import Fore, Style, init
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

init(autoreset=True, strip=not sys.stdout.isatty())


class SiteConfigError(ValueError):
    """Raised when a site definition is invalid."""


@dataclass(frozen=True)
class Site:
    """Configuration for a single platform lookup."""

    name: str
    url: str
    method: str
    category: str
    expect: Optional[int] = None
    pattern: Optional[str] = None

    def build_url(self, username: str) -> str:
        return self.url.format(username)

    @classmethod
    def from_mapping(cls, payload: Dict[str, object]) -> "Site":
        try:
            name = str(payload["name"])
            url = str(payload["url"])
            method = str(payload["method"]).lower()
            category = str(payload.get("category", "uncategorised"))
        except KeyError as exc:  # pragma: no cover - defensive guard
            raise SiteConfigError(f"Missing required field {exc} in site payload: {payload}") from exc

        expect = payload.get("expect")
        pattern = payload.get("pattern")

        if method not in {"status", "pattern"}:
            raise SiteConfigError(
                f"Unsupported method '{method}' for site '{name}'. Expected 'status' or 'pattern'."
            )

        if method == "status" and expect is None:
            raise SiteConfigError(f"Site '{name}' (status) requires an 'expect' value for not-found comparisons.")

        if method == "pattern" and not pattern:
            raise SiteConfigError(f"Site '{name}' (pattern) requires a 'pattern' value for not-found detection.")

        return cls(name=name, url=url, method=method, category=category, expect=expect, pattern=pattern)


@dataclass
class SiteCheckResult:
    """Outcome for a site lookup."""

    site: Site
    exists: Optional[bool]
    url: str
    response_time: Optional[float] = None
    error: Optional[str] = None

    @property
    def status_label(self) -> str:
        if self.exists is True:
            return "Found"
        if self.exists is False:
            return "Not Found"
        return "Unknown"


DEFAULT_SITE_DATA: Sequence[Dict[str, object]] = (
    {"name": "Instagram", "url": "https://instagram.com/{}", "method": "status", "expect": 404, "category": "social"},
    {"name": "Facebook", "url": "https://facebook.com/{}", "method": "status", "expect": 404, "category": "social"},
    {"name": "Twitter", "url": "https://twitter.com/{}", "method": "pattern", "pattern": "page doesn't exist", "category": "social"},
    {"name": "TikTok", "url": "https://tiktok.com/@{}", "method": "status", "expect": 404, "category": "social"},
    {"name": "YouTube", "url": "https://youtube.com/@{}", "method": "status", "expect": 404, "category": "media"},
    {"name": "Reddit", "url": "https://reddit.com/user/{}", "method": "pattern", "pattern": "page not found", "category": "forum"},
    {"name": "Pinterest", "url": "https://pinterest.com/{}", "method": "status", "expect": 404, "category": "social"},
    {"name": "LinkedIn", "url": "https://linkedin.com/in/{}", "method": "status", "expect": 404, "category": "professional"},
    {"name": "GitHub", "url": "https://github.com/{}", "method": "status", "expect": 404, "category": "tech"},
    {"name": "Twitch", "url": "https://twitch.tv/{}", "method": "status", "expect": 404, "category": "streaming"},
    {"name": "Snapchat", "url": "https://snapchat.com/add/{}", "method": "status", "expect": 404, "category": "social"},
    {"name": "Telegram", "url": "https://t.me/{}", "method": "status", "expect": 404, "category": "social"},
    {"name": "Discord", "url": "https://discord.com/users/{}", "method": "status", "expect": 404, "category": "social"},
    {"name": "Quora", "url": "https://quora.com/profile/{}", "method": "pattern", "pattern": "profile not found", "category": "forum"},
    {"name": "Medium", "url": "https://medium.com/@{}", "method": "status", "expect": 404, "category": "blogging"},
    {"name": "Vimeo", "url": "https://vimeo.com/{}", "method": "status", "expect": 404, "category": "media"},
    {"name": "Flickr", "url": "https://flickr.com/people/{}", "method": "status", "expect": 404, "category": "photography"},
    {"name": "Dribbble", "url": "https://dribbble.com/{}", "method": "status", "expect": 404, "category": "design"},
    {"name": "Behance", "url": "https://behance.net/{}", "method": "status", "expect": 404, "category": "design"},
    {"name": "DeviantArt", "url": "https://{}.deviantart.com", "method": "status", "expect": 404, "category": "art"},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{}", "method": "status", "expect": 404, "category": "music"},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{}", "method": "status", "expect": 404, "category": "music"},
    {"name": "Steam", "url": "https://steamcommunity.com/id/{}", "method": "status", "expect": 404, "category": "gaming"},
    {"name": "Xbox", "url": "https://xboxgamertag.com/search/{}", "method": "pattern", "pattern": "not found", "category": "gaming"},
    {"name": "PlayStation", "url": "https://psnprofiles.com/{}", "method": "status", "expect": 404, "category": "gaming"},
    {"name": "StackOverflow", "url": "https://stackoverflow.com/users/{}", "method": "status", "expect": 404, "category": "tech"},
    {"name": "GitLab", "url": "https://gitlab.com/{}", "method": "status", "expect": 404, "category": "tech"},
    {"name": "Bitbucket", "url": "https://bitbucket.org/{}", "method": "status", "expect": 404, "category": "tech"},
    {"name": "Ebay", "url": "https://www.ebay.com/usr/{}", "method": "status", "expect": 404, "category": "shopping"},
    {"name": "Etsy", "url": "https://www.etsy.com/shop/{}", "method": "status", "expect": 404, "category": "shopping"},
    {"name": "Kaggle", "url": "https://www.kaggle.com/{}", "method": "status", "expect": 404, "category": "tech"},
    {"name": "Keybase", "url": "https://keybase.io/{}", "method": "status", "expect": 404, "category": "security"},
    {"name": "Last.fm", "url": "https://www.last.fm/user/{}", "method": "status", "expect": 404, "category": "music"},
)


DEFAULT_SITES: Tuple[Site, ...] = tuple(Site.from_mapping(item) for item in DEFAULT_SITE_DATA)


def build_banner(version: str) -> str:
    return (
        f"""
{Fore.RED}
MMMMSSSSSSSSSSSSSSSSMSS;.     .dMMMMSSSSSSMMSSSSSSSSS
MMSSSSSSSMSSSSSMSSSSMMMSS."-.-":MMMMMSSSSMMMMSSMSSSMMS
MSSSSSSSMSSSSMMMSSMMMPTMM;"-/\\":MMM^"     MMMSSMMMSSMM
SSSSSSSMMSSMMMMMMMMMP-.MMM :  ;.;P       dMMMMMMMMMP'
SSMSSSMMMSMMMMMMMMMP   :M;`:  ;.'+\"""t+dMMMMMMMMMMP
MMMSSMMMMMMMMPTMMMM\"""":P `.\// '    ""^^MMMMMMMP'
MMMMMMPTMMMMP="TMMMsg,      \/   db`c"  dMMMMMP"
MMMMMM  TMMM   d$$$b ^          /T$; ;-/TMMMP
MMMMM; .^`M; d$P^T$$b          :  $$ ::  "T(
MMMMMM   .-+d$$   $$$;         ; d$$ ;;  __
MMMMMMb   _d$$$   $$$$         :$$$; :MmMMMMp.
MMMMMM"  " T$$$._.$$$;          T$P.'MMMSSSSSSb.
MMM`TMb   -")T$$$$$$P'       `._ ""  :MMSSSMMP'
MMM / \\    '  "T$$P"           /     :MMMMMMM
MMSb`. ;                      "      :MMMMMMM
MMSSb_lSSSb.      \\ `.   .___.       MMMMMMMM
MMMMSSSSSSSSb.                     .MMMMMMMMM
MMMMMMMMMMMMSSSb                  .dMMMMMMMMM'
MMMMMMMMMMMMMSS;               .dMMMMMMMMMMP
MMMMMMMMMMMMMMb`;"-.          .dMMMMMMMMMMP'
MMMMMMMMMMMMMMb    ""--.___.dMMMMMMMMMP^"
{Fore.CYAN}
01001000 01101001 01100100 01100100 01100101 01101110 01000101 01111001 01100101 01110011 01010100 01100101 01100001 01101101
01001000 01101001 01100100 01100100 01100101 01101110 01000101 01111001 01100101 01110011 01010100 01100101 01100001 01101101
01001000 01101001 01100100 01100100 01100101 01101110 01000101 01111001 01100101 01110011 01010100 01100101 01100001 01101101
01001000 01101001 01100100 01100100 01100101 01101110 01000101 01111001 01100101 01110011 01010100 01100101 01100001 01101101
01001000 01101001 01100100 01100100 01100101 01101110 01000101 01111001 01100101 01110011 01010100 01100101 01100001 01101101
{Fore.YELLOW}RITHCYBER-TEAM | OSINT Tool v{version}
{Style.RESET_ALL}
"""
    )


class UsernameHunter:
    """Concurrent username OSINT scanner with configurable providers."""

    def __init__(
        self,
        *,
        sites: Optional[Sequence[Site]] = None,
        timeout: float = 15.0,
        max_threads: int = 25,
        retries: int = 2,
        delay_range: Tuple[float, float] = (0.35, 1.25),
        headers: Optional[Dict[str, str]] = None,
        version: str = "2.0",
    ) -> None:
        if max_threads < 1:
            raise ValueError("max_threads must be at least 1")

        self.version = version
        self._all_sites: Tuple[Site, ...] = tuple(sites or DEFAULT_SITES)
        self.timeout = timeout
        self.max_threads = max_threads
        self.retries = retries
        self.delay_range = self._normalise_delay(delay_range)
        self.headers = headers or {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
            ),
            "Accept-Language": "en-US,en;q=0.9",
        }

        self.session = requests.Session()
        self._configure_session()

        self.banner = build_banner(self.version)

        self.username: Optional[str] = None
        self.results: List[SiteCheckResult] = []
        self.found: List[SiteCheckResult] = []
        self.not_found: List[SiteCheckResult] = []
        self.unknown: List[SiteCheckResult] = []
        self.errors: List[str] = []

    @staticmethod
    def _normalise_delay(delay_range: Tuple[float, float]) -> Tuple[float, float]:
        minimum, maximum = delay_range
        if minimum < 0 or maximum < 0:
            raise ValueError("Delay values must be non-negative")
        if maximum < minimum:
            raise ValueError("Maximum delay must be greater than or equal to minimum delay")
        return minimum, maximum

    def _configure_session(self) -> None:
        retry_strategy = Retry(
            total=self.retries,
            backoff_factor=0.8,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("HEAD", "GET", "OPTIONS"),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    @property
    def sites(self) -> Tuple[Site, ...]:
        return self._all_sites

    def reset_state(self) -> None:
        self.results.clear()
        self.found.clear()
        self.not_found.clear()
        self.unknown.clear()
        self.errors.clear()

    @staticmethod
    def load_sites_from_file(path: Path) -> Tuple[Site, ...]:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)

        if not isinstance(payload, Iterable):
            raise SiteConfigError("Site file must contain an iterable of site definitions")

        sites = [Site.from_mapping(item) for item in payload]
        if not sites:
            raise SiteConfigError("Site file did not contain any usable site definitions")
        return tuple(sites)

    @staticmethod
    def _normalise_filters(values: Optional[Sequence[str]]) -> Optional[Tuple[str, ...]]:
        if not values:
            return None
        return tuple(value.strip().lower() for value in values if value and value.strip()) or None

    def _select_sites(
        self,
        *,
        include_categories: Optional[Sequence[str]] = None,
        exclude_categories: Optional[Sequence[str]] = None,
        include_sites: Optional[Sequence[str]] = None,
        exclude_sites: Optional[Sequence[str]] = None,
    ) -> List[Site]:
        include_categories = self._normalise_filters(include_categories)
        exclude_categories = self._normalise_filters(exclude_categories)
        include_sites = self._normalise_filters(include_sites)
        exclude_sites = self._normalise_filters(exclude_sites)

        selected: List[Site] = []
        for site in self._all_sites:
            site_name = site.name.lower()
            site_category = site.category.lower()

            if include_categories and site_category not in include_categories:
                continue
            if exclude_categories and site_category in exclude_categories:
                continue
            if include_sites and site_name not in include_sites:
                continue
            if exclude_sites and site_name in exclude_sites:
                continue

            selected.append(site)

        return selected

    def _resolve_threads(self, total_sites: int) -> int:
        return max(1, min(self.max_threads, total_sites))

    def _interpret_response(self, site: Site, response: requests.Response) -> Optional[bool]:
        if response.status_code == 429:
            # explicit rate limit - let caller treat as error/unknown
            return None

        if site.method == "status":
            expected_status = site.expect
            if isinstance(expected_status, (list, tuple, set)):
                expected_statuses = set(expected_status)
            else:
                expected_statuses = {int(expected_status)}
            return response.status_code not in expected_statuses

        if site.method == "pattern":
            if site.pattern is None:
                raise SiteConfigError(f"Site '{site.name}' missing detection pattern.")
            return site.pattern.lower() not in response.text.lower()

        raise SiteConfigError(f"Unsupported method '{site.method}' for site '{site.name}'.")

    def _maybe_sleep(self) -> None:
        minimum, maximum = self.delay_range
        if maximum == 0:
            return
        time.sleep(random.uniform(minimum, maximum))

    def check_username(self, site: Site, username: str) -> SiteCheckResult:
        url = site.build_url(username)
        try:
            self._maybe_sleep()
            start = time.perf_counter()
            response = self.session.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            elapsed = time.perf_counter() - start
            exists = self._interpret_response(site, response)

            if response.status_code == 429:
                error = "Rate limited (HTTP 429)"
                return SiteCheckResult(site=site, exists=None, url=url, response_time=elapsed, error=error)

            return SiteCheckResult(site=site, exists=exists, url=url, response_time=elapsed)

        except requests.RequestException as exc:
            return SiteCheckResult(site=site, exists=None, url=url, error=str(exc))

    def export_results(self, export_format: str, export_dir: Optional[Path] = None) -> Path:
        export_format = export_format.lower()
        if export_format not in {"json", "csv", "md", "markdown"}:
            raise ValueError(f"Unsupported export format '{export_format}'.")

        export_dir = (export_dir or Path.cwd()).expanduser().resolve()
        export_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = export_dir / f"username_report_{timestamp}"

        if export_format == "json":
            payload = {
                "username": self.username,
                "timestamp": datetime.now().isoformat(),
                "found": [self._result_to_dict(result) for result in self.found],
                "not_found": [self._result_to_dict(result) for result in self.not_found],
                "unknown": [self._result_to_dict(result) for result in self.unknown],
                "errors": list(self.errors),
            }
            path = filename.with_suffix(".json")
            with path.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=4)
            return path

        if export_format == "csv":
            path = filename.with_suffix(".csv")
            with path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(["Platform", "URL", "Status", "Category", "Response Time (s)"])
                for result in self.results:
                    writer.writerow(
                        [
                            result.site.name,
                            result.url,
                            result.status_label,
                            result.site.category,
                            f"{result.response_time:.2f}" if result.response_time is not None else "",
                        ]
                    )
            return path

        if export_format in {"md", "markdown"}:
            path = filename.with_suffix(".md")
            with path.open("w", encoding="utf-8") as handle:
                handle.write(f"# Username Scan Report for `{self.username}`\n\n")
                handle.write(f"Generated: {datetime.now().isoformat()}\n\n")
                handle.write("| Platform | Status | Category | Response Time (s) | URL |\n")
                handle.write("|----------|--------|----------|-------------------|-----|\n")
                for result in self.results:
                    time_value = f"{result.response_time:.2f}" if result.response_time is not None else ""
                    handle.write(
                        f"| {result.site.name} | {result.status_label} | {result.site.category} | {time_value} | {result.url} |\n"
                    )
                if self.errors:
                    handle.write("\n## Errors\n\n")
                    for error in self.errors:
                        handle.write(f"- {error}\n")
            return path

        raise ValueError(f"Unexpected export format '{export_format}'.")

    @staticmethod
    def _result_to_dict(result: SiteCheckResult) -> Dict[str, object]:
        return {
            "site": result.site.name,
            "url": result.url,
            "status": result.status_label,
            "category": result.site.category,
            "response_time": result.response_time,
            "error": result.error,
        }

    def _record_result(self, result: SiteCheckResult) -> None:
        self.results.append(result)
        if result.exists is True:
            self.found.append(result)
        elif result.exists is False:
            self.not_found.append(result)
        else:
            self.unknown.append(result)
        if result.error:
            self.errors.append(f"{result.site.name}: {result.error}")

    def run(
        self,
        username: str,
        *,
        export: Optional[str] = None,
        export_dir: Optional[Path] = None,
        show_banner: bool = True,
        show_errors: bool = False,
        include_categories: Optional[Sequence[str]] = None,
        exclude_categories: Optional[Sequence[str]] = None,
        include_sites: Optional[Sequence[str]] = None,
        exclude_sites: Optional[Sequence[str]] = None,
    ) -> List[SiteCheckResult]:
        self.reset_state()
        self.username = username

        sites = self._select_sites(
            include_categories=include_categories,
            exclude_categories=exclude_categories,
            include_sites=include_sites,
            exclude_sites=exclude_sites,
        )

        if not sites:
            raise ValueError("No sites selected. Adjust filtering options.")

        if show_banner:
            print(self.banner)

        print(f"\n{Fore.CYAN}[??] {Fore.WHITE}Target Username: {Fore.YELLOW}{username}")
        print(f"{Fore.CYAN}[?] {Fore.WHITE}Scanning {Fore.GREEN}{len(sites)} {Fore.WHITE}platforms\n")

        start = time.perf_counter()

        from concurrent.futures import ThreadPoolExecutor, as_completed

        with ThreadPoolExecutor(max_workers=self._resolve_threads(len(sites))) as executor:
            future_to_site = {executor.submit(self.check_username, site, username): site for site in sites}

            for future in as_completed(future_to_site):
                site = future_to_site[future]
                try:
                    result = future.result()
                except Exception as exc:  # pragma: no cover - defensive guard
                    error_result = SiteCheckResult(site=site, exists=None, url=site.build_url(username), error=str(exc))
                    self._record_result(error_result)
                    self._print_site_output(error_result)
                else:
                    self._record_result(result)
                    self._print_site_output(result)

        elapsed = time.perf_counter() - start
        self._print_summary(elapsed)

        if show_errors and self.errors:
            self._print_errors()

        if export:
            path = self.export_results(export, export_dir)
            print(f"\n{Fore.CYAN}[??] {Fore.WHITE}Report saved to {Fore.YELLOW}{path}")

        return self.results

    def _print_site_output(self, result: SiteCheckResult) -> None:
        response_time = f" {Fore.MAGENTA}{result.response_time:.2f}s" if result.response_time else ""
        if result.exists is True:
            print(f"{Fore.GREEN}[?] {result.site.name}{response_time}")
        elif result.exists is False:
            print(f"{Fore.RED}[?] {result.site.name}{response_time}")
        else:
            status = result.error or "Unknown response"
            print(f"{Fore.YELLOW}[?] {result.site.name} ? {status}")

    def _print_summary(self, elapsed: float) -> None:
        print(
            f"\n{Fore.CYAN}[+] {Fore.WHITE}Scan completed in {Fore.YELLOW}{elapsed:.2f}s"
        )
        print(
            f"{Fore.CYAN}[+] {Fore.GREEN}{len(self.found)} {Fore.WHITE}Found | "
            f"{Fore.RED}{len(self.not_found)} {Fore.WHITE}Not Found | "
            f"{Fore.YELLOW}{len(self.unknown)} {Fore.WHITE}Unknown"
        )

    def _print_errors(self) -> None:
        print(f"\n{Fore.YELLOW}[!] {Fore.WHITE}Encountered {len(self.errors)} issue(s):")
        for error in self.errors:
            print(f"  - {error}")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="HiddenEyes Username Scanner (upgraded)")
    parser.add_argument("username", nargs="?", help="Target username to search")
    parser.add_argument("-e", "--export", choices=["json", "csv", "md", "markdown"], help="Export results format")
    parser.add_argument("--export-dir", type=Path, help="Directory to write exported reports")
    parser.add_argument("--max-threads", type=int, help="Override maximum number of concurrent requests")
    parser.add_argument("--timeout", type=float, help="Request timeout in seconds")
    parser.add_argument("--retries", type=int, default=2, help="Number of retry attempts for transient failures")
    parser.add_argument("--delay", nargs=2, type=float, metavar=("MIN", "MAX"), help="Random delay range between requests")
    parser.add_argument("--include-category", action="append", help="Only scan platforms matching this category (can repeat)")
    parser.add_argument("--exclude-category", action="append", help="Skip platforms in this category (can repeat)")
    parser.add_argument("--include-site", action="append", help="Only scan these site names (case-insensitive, can repeat)")
    parser.add_argument("--exclude-site", action="append", help="Skip these site names (case-insensitive, can repeat)")
    parser.add_argument("--sites-file", type=Path, help="Path to a JSON file with custom site definitions")
    parser.add_argument("--no-banner", action="store_true", help="Suppress ASCII art banner")
    parser.add_argument("--show-errors", action="store_true", help="Display network or parsing errors at the end")
    parser.add_argument("--list-sites", action="store_true", help="List platform names and exit")

    args = parser.parse_args(argv)

    if args.list_sites and not args.username:
        return args

    if not args.username:
        parser.error("username is required unless --list-sites is used")

    if args.delay and args.delay[1] < args.delay[0]:
        parser.error("Maximum delay must be greater than or equal to minimum delay")

    return args


def list_sites(sites: Sequence[Site]) -> None:
    print(f"Available platforms ({len(sites)} total):\n")
    for site in sorted(sites, key=lambda s: (s.category.lower(), s.name.lower())):
        print(f"- {site.name} [{site.category}] -> {site.url}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)

    sites: Tuple[Site, ...] = DEFAULT_SITES
    if args.sites_file:
        try:
            sites = UsernameHunter.load_sites_from_file(args.sites_file)
        except (OSError, SiteConfigError, json.JSONDecodeError) as exc:
            print(f"{Fore.RED}Failed to load site configuration: {exc}{Style.RESET_ALL}")
            return 1

    if args.list_sites:
        list_sites(sites)
        return 0

    delay_range: Tuple[float, float] = (0.35, 1.25)
    if args.delay:
        delay_range = (args.delay[0], args.delay[1])

    hunter = UsernameHunter(
        sites=sites,
        timeout=args.timeout if args.timeout is not None else 15.0,
        max_threads=args.max_threads if args.max_threads is not None else 25,
        retries=args.retries,
        delay_range=delay_range,
    )

    try:
        hunter.run(
            args.username,
            export=args.export,
            export_dir=args.export_dir,
            show_banner=not args.no_banner,
            show_errors=args.show_errors,
            include_categories=args.include_category,
            exclude_categories=args.exclude_category,
            include_sites=args.include_site,
            exclude_sites=args.exclude_site,
        )
    except (requests.RequestException, ValueError) as exc:
        print(f"{Fore.RED}Scan failed: {exc}{Style.RESET_ALL}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
