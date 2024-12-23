# Burp Swagger Scanner

This Burp Suite extension dynamically finds Swagger JSON or documentation endpoints and creates security issues in the Burp Suite Issues tab.

## Features
- Passive and active scanning for Swagger endpoints.
- Automatically generates medium severity issues for discovered Swagger endpoints.

## Installation
1. Clone this repository or download the `swagger-scanner.py` file.
2. Load the extension into Burp Suite:
   - Go to `Extender > Extensions > Add`.
   - Select the `swagger-scanner.py` file.

## Usage
- Start a new scan or proxy traffic through Burp Suite.
- Discovered Swagger endpoints will appear in the Issues tab.

## License
MIT License
