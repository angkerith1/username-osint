import requests
import concurrent.futures
import json
import time
import random
import argparse
from datetime import datetime
import csv
from colorama import Fore, Style, init

init(autoreset=True)

class UsernameHunter:
    def __init__(self):
        self.version = "4.0"
        self.session = requests.Session()
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        self.timeout = 15
        self.max_threads = 25
        self.retries = 2
        self.delay = random.uniform(0.5, 1.5)
        self.found = []
        self.not_found = []
        self.errors = []

        self.banner = fr"""
{Fore.RED}
MMMMSSSSSSSSSSSSSSSSMSS;.     .dMMMMSSSSSSMMSSSSSSSSS
MMSSSSSSSMSSSSSMSSSSMMMSS."-.-":MMMMMSSSSMMMMSSMSSSMMS
MSSSSSSSMSSSSMMMSSMMMPTMM;"-/\":MMM^"     MMMSSMMMSSMM
SSSSSSSMMSSMMMMMMMMMP-.MMM :  ;.;P       dMMMMMMMMMP'
SSMSSSMMMSMMMMMMMMMP   :M;`:  ;.'+\"\"\"t+dMMMMMMMMMMP
MMMSSMMMMMMMMPTMMMM\"\"\"\":P `.\// '    \"\"^^MMMMMMMP'
MMMMMMPTMMMMP="TMMMsg,      \/   db`c"  dMMMMMP"
MMMMMM  TMMM   d$$$b ^          /T$; ;-/TMMMP
MMMMM; .^`M; d$P^T$$b          :  $$ ::  "T(
MMMMMM   .-+d$$   $$$;         ; d$$ ;;  __
MMMMMMb   _d$$$   $$$$         :$$$; :MmMMMMp.
MMMMMM"  " T$$$._.$$$;          T$P.'MMMSSSSSSb.
MMM`TMb   -")T$$$$$$P'       `._ ""  :MMSSSMMP'
MMM / \    '  "T$$P"           /     :MMMMMMM
MMSb`. ;                      "      :MMMMMMM
MMSSb_lSSSb.      \ `.   .___.       MMMMMMMM
MMMMSSSSSSSSb.                     .MMMMMMMMM
MMMMMMMMMMMSSSb                  .dMMMMMMMMM'
MMMMMMMMMMMMMSS;               .dMMMMMMMMMMP
MMMMMMMMMMMMMb`;"-.          .dMMMMMMMMMMP'
MMMMMMMMMMMMMMb    ""--.___.dMMMMMMMMMP^"
{Fore.CYAN}
01001000 01101001 01100100 01100100 01100101 01101110 01000101 01111001 01100101 01110011 01010100 01100101 01100001 01101101
01001000 01101001 01100100 01100100 01100101 01101110 01000101 01111001 01100101 01110011 01010100 01100101 01100001 01101101
01001000 01101001 01100100 01100100 01100101 01101110 01000101 01111001 01100101 01110011 01010100 01100101 01100001 01101101
01001000 01101001 01100100 01100100 01100101 01101110 01000101 01111001 01100101 01110011 01010100 01100101 01100001 01101101
01001000 01101001 01100100 01100100 01100101 01101110 01000101 01111001 01100101 01110011 01010100 01100101 01100001 01101101
{Fore.YELLOW}RITHCYBER-TEAM | OSINT Tool v{self.version}
{Style.RESET_ALL}"""

        self.sites = [
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
            {"name": "Etsy", "url": "https://www.etsy.com/shop/{}", "method": "status", "expect": 404, "category": "shopping"}
        ]

    def print_banner(self):
        print(self.banner)

    def check_username(self, site, username):
        url = site['url'].format(username)
        for _ in range(self.retries):
            try:
                time.sleep(self.delay)
                response = self.session.get(url, headers=self.headers, timeout=self.timeout)

                if site['method'] == 'status':
                    if response.status_code == site['expect']:
                        return False
                    return True

                elif site['method'] == 'pattern':
                    if site['pattern'].lower() in response.text.lower():
                        return False
                    return True

            except Exception as e:
                self.errors.append(f"{site['name']}: {str(e)}")
                continue
        return None

    def export_results(self, format='json'):
        filename = f"username_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        if format == 'json':
            with open(f"{filename}.json", 'w') as f:
                json.dump({
                    "username": self.username,
                    "found": self.found,
                    "not_found": self.not_found,
                    "errors": self.errors,
                    "timestamp": str(datetime.now())
                }, f, indent=4)

        elif format == 'csv':
            with open(f"{filename}.csv", 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Platform', 'URL', 'Status', 'Category'])
                for item in self.found + self.not_found:
                    writer.writerow([item['site'], item['url'], item['status'], item['category']])

    def run(self, username, export=None):
        self.username = username
        self.print_banner()

        print(f"\n{Fore.CYAN}[🔍] {Fore.WHITE}Target Username: {Fore.YELLOW}{username}")
        print(f"{Fore.CYAN}[ℹ] {Fore.WHITE}Scanning {Fore.GREEN}{len(self.sites)} {Fore.WHITE}platforms\n")

        start_time = time.time()

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.check_username, site, username): site for site in self.sites}

            for future in concurrent.futures.as_completed(futures):
                site = futures[future]
                try:
                    result = future.result()
                    if result is True:
                        self.found.append({
                            "site": site['name'],
                            "url": site['url'].format(username),
                            "status": "Found",
                            "category": site['category']
                        })
                        print(f"{Fore.GREEN}[✓] {site['name']}")
                    elif result is False:
                        self.not_found.append({
                            "site": site['name'],
                            "url": site['url'].format(username),
                            "status": "Not Found",
                            "category": site['category']
                        })
                        print(f"{Fore.RED}[✗] {site['name']}")
                except Exception as e:
                    self.errors.append(str(e))

        elapsed_time = time.time() - start_time
        print(f"\n{Fore.CYAN}[+] {Fore.WHITE}Scan completed in {Fore.YELLOW}{elapsed_time:.2f}s")
        print(f"{Fore.CYAN}[+] {Fore.GREEN}{len(self.found)} {Fore.WHITE}Found | {Fore.RED}{len(self.not_found)} {Fore.WHITE}Not Found | {Fore.YELLOW}{len(self.errors)} {Fore.WHITE}Errors")

        if export:
            self.export_results(export)
            print(f"\n{Fore.CYAN}[💾] {Fore.WHITE}Report saved as {Fore.YELLOW}{export.upper()}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HiddenEyes Username Scanner")
    parser.add_argument("username", help="Target username to search")
    parser.add_argument("-e", "--export", choices=['json', 'csv'], help="Export results format")
    args = parser.parse_args()

    tool = UsernameHunter()
    tool.run(args.username, args.export)