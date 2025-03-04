# phpMyAdmin Brute-Force Tool with Resume Feature

## Overview

The **phpMyAdmin Brute-Force Tool** is a Python script designed for brute-forcing phpMyAdmin login credentials with the option to resume the attack in case of interruptions. It utilizes a wordlist of passwords, and ensures that progress is saved, allowing you to pick up right where you left off, making it efficient for long-running attacks. The tool also features controlled concurrency to avoid overwhelming the server.

### Key Features
- **Resume Support**: Saves progress to a file, allowing you to resume the brute-force attack without starting over.
- **Semaphore for Concurrency**: Limits the number of concurrent requests to avoid server overload and detection.
- **Simple & Easy to Use**: Just provide the URL, username, and password wordlist, and the tool will handle the rest.
- **Error Handling**: Handles connection errors and displays relevant messages to help diagnose issues.
- **Color-Coded Output**: Provides clear, color-coded feedback in the terminal using `colorama`.

## Prerequisites

Before running this tool, make sure you have the following installed:

- Python 3.x
- `requests` library (Install using `pip install requests`)
- `colorama` library (Install using `pip install colorama`)

## Installation

1. Clone the repository to your local machine:

    ```bash
    git clone https://github.com/mrdodgerx/phpmyadmin-bruteforce-tool.git
    cd phpmyadmin-bruteforce-tool
    ```

2. Install the required dependencies:

    ```bash
    pip install -r requirements.txt
    ```

3. Make sure the script is executable:

    ```bash
    chmod +x phpmyadmin-cracker.py
    ```

## Usage

To run the brute-force attack, use the following command:

```bash
python phpmyadmin-cracker.py --url <phpMyAdmin URL> --username <username> --wordlist <path-to-wordlist>
```

### Arguments:
- `--url` (required): The URL of the target phpMyAdmin login page (e.g., `http://target-site.com/phpmyadmin`).
- `--username` (required): The username for the phpMyAdmin login.
- `--wordlist` (required): Path to the wordlist file containing potential passwords.

## Example

```bash
python phpmyadmin-cracker.py --url http://localhost/phpmyadmin --username root --wordlist /path/to/wordlist.txt
```

## Contributing

Feel free to fork the repository, submit issues, and open pull requests. Contributions are always welcome.

1. Fork this repository.
2. Create your feature branch (`git checkout -b feature-name`).
3. Commit your changes (`git commit -am 'Add new feature'`).
4. Push to the branch (`git push origin feature-name`).
5. Open a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
