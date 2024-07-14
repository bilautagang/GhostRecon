# GhostRecon

GhostRecon is a website reconnaissance tool written in Go that automates the process of discovering subdomains, checking their availability, and capturing screenshots of live subdomains.

## Features

- Uses multiple subdomain discovery tools (`subfinder`, `assetfinder`, `dnsrecon`, `findomain`) to gather subdomains associated with a target website.
- Checks the status of each subdomain to determine if it is live or dead.
- Captures screenshots of live subdomains using `aquatone`.
- Removes duplicate subdomains and saves unique results to a master file.

## Prerequisites

Before using GhostRecon, ensure you have the following tools installed and available in your PATH:

- `subfinder`: https://github.com/projectdiscovery/subfinder
- `assetfinder`: https://github.com/tomnomnom/assetfinder
- `dnsrecon`: https://github.com/darkoperator/dnsrecon
- `findomain`: https://github.com/Edu4rdSHL/findomain
- `aquatone`: https://github.com/michenriksen/aquatone

## Installation

Clone the repository:

```bash
git clone https://github.com/bilautagang/GhostRecon.git
cd GhostRecon
# GhostRecon

GhostRecon is a website reconnaissance tool written in Go that automates the process of discovering subdomains, checking their availability, and capturing screenshots of live subdomains.

## Features

- Uses multiple subdomain discovery tools (`subfinder`, `assetfinder`, `dnsrecon`, `findomain`) to gather subdomains associated with a target website.
- Checks the status of each subdomain to determine if it is live or dead.
- Captures screenshots of live subdomains using `aquatone`.
- Removes duplicate subdomains and saves unique results to a master file.

## Prerequisites

Before using GhostRecon, ensure you have the following tools installed and available in your PATH:

- `subfinder`: https://github.com/projectdiscovery/subfinder
- `assetfinder`: https://github.com/tomnomnom/assetfinder
- `dnsrecon`: https://github.com/darkoperator/dnsrecon
- `findomain`: https://github.com/Edu4rdSHL/findomain
- `aquatone`: https://github.com/michenriksen/aquatone

## Installation

Clone the repository:

git clone https://github.com/bilautagang/GhostRecon.git
cd GhostRecon

Ensure Go is installed on your system. Then, run:

go build

## Usage

    1. Run GhostRecon:
./GhostRecon

    2. Enter the website URL when prompted.

    3. GhostRecon will create an output directory and start gathering subdomains, checking their status, and capturing screenshots of live subdomains.
