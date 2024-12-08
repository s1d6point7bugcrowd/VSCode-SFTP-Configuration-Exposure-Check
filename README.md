# VSCode SFTP Configuration Exposure Check

This repository contains a configuration for detecting exposed **VSCode SFTP** configuration files (`sftp.json`) and a `curl` script to verify its existence and check for sensitive information.

## Overview

The `.vscode/sftp.json` file is used by Visual Studio Code to store SFTP configuration settings for remote file transfer. If exposed, it can leak sensitive information, such as usernames, passwords, protocol types, and port numbers. This repository contains:

- A **YAML configuration** to test for exposed `.vscode/sftp.json` files.
- A **`curl` script** to verify the existence and content of the file.

## YAML Configuration: VSCode SFTP Exposure Test

The following YAML configuration checks for exposed VSCode SFTP configuration files by searching for sensitive data within the `.vscode/sftp.json` file. It uses the status code `200` (OK) and checks for the presence of sensitive words like `username`, `password`, `protocol`, and `port`.

```yaml
id: vscode-sftp-exposure

info:
  name: VSCode SFTP Configuration Exposure
  author: SirBugs
  severity: high
  description: Checks for exposed VSCode SFTP configuration file.
  tags: exposure

requests:
  - method: GET
    path:
      - "{{BaseURL}}/.vscode/sftp.json"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200  # Ensure the response status is 200 OK (or other valid success status)
      - type: word
        condition: or
        words:
          - '"protocol":'
          - '"port":'
          - '"username":'
          - '"password":'
        part: body



Verify Exposed VSCode SFTP Configuration Using curl

You can use the following curl command to verify whether the .vscode/sftp.json file is exposed and contains sensitive information:


curl -s -w "%{http_code}" -o response.txt "target" | \
    tee response.txt | \
    grep -q "200" && grep -E '"protocol":|"port":|"username":|"password":' response.txt && echo "Sensitive information found" || echo "No sensitive information found or 404"
