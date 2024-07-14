NVD CVE Information Extractor
=======================

Purpose
-------

The `CVE Information Fetcher` script is designed to help users retrieve and display information about Common Vulnerabilities and Exposures (CVEs) from the National Vulnerability Database (NVD). The script uses the NVD CVE API 2.0 to fetch details about specified CVE IDs and presents this information in a readable format in the terminal.

Features
--------

-   Fetch CVE information using the NVD CVE API 2.0.
-   Display CVE ID, description, CVSS metrics, and known affected software configurations.
-   Extract and list the criteria strings from the configurations.

Requirements
------------

-   A valid NVD CVE API key (that can be aquired by requesting it in the following link: https://nvd.nist.gov/developers/request-an-api-key).

Setup
-----

1.  **API Key:** You must have a valid NVD CVE API key. Insert your API key in the `API_KEY` variable in the script.

Usage
-----

1.  **Install Dependencies:** The script requires the `requests` library to make API calls. You can install it using pip:

-   pip install requests

2.  **Run the Script:** Execute the script and input the CVE IDs you want to know about when prompted. The CVE IDs should be comma-separated.

-   python nvd_cve_extractor.py

3. Example Input:

-   Enter the CVE IDs you want to know about (comma-separated): CVE-2021-34527, CVE-2020-0601

Code Explanation
----------------

### fetch_cve_info(cve_id)

This function takes a CVE ID as input, sends a GET request to the NVD API, and returns the JSON response containing the CVE information.

### extract_criteria(configurations)

This function extracts and returns the criteria strings from the configurations list. It navigates through the nested configurations data structure to find and collect all `criteria` strings.

### display_cve_info(cve_info)

This function displays the fetched CVE information in the terminal. It prints the CVE ID, description, CVSS metrics, and known affected software configurations by calling the `extract_criteria` function.

### main()

The main function prompts the user to input CVE IDs, fetches information for each CVE ID using `fetch_cve_info`, and displays the information using `display_cve_info`.

Example Output
--------------

+------------------------------------------------------------------------------+\
CVE ID: CVE-2021-34527\
Description: A remote code execution vulnerability exists in Windows Print Spooler software...

CVSS Metrics:\
CVSS Version 3.1:\
  Severity: Critical\
  Base Score: 9.8\
  Impact Score: 6.0\
  Exploitability Score: 3.9\
  Vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

Known Affected Software Configurations:\
  CPE: cpe:2.3:a:vendor:software:version:*:*:*:*:*:*:*\
+------------------------------------------------------------------------------+

Note
----

Ensure to replace the placeholder API key with your actual API key in the `API_KEY` variable:
API_KEY = 'insert-your-api-key-here'

This script is a useful tool for security professionals and developers to quickly gather and review CVE information, aiding in vulnerability management and remediation efforts.
