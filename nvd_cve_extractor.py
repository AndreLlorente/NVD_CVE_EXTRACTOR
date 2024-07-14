import requests

# Define the base URL for the NVD CVE API 2.0
BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

# Your API key
API_KEY = 'insert-your-api-key-here'

def fetch_cve_info(cve_id):
    """
    Fetch information about a specific CVE from the NVD API 2.0.
    """
    headers = {
        'apiKey': API_KEY  # Include the API key in the request headers
    }
    response = requests.get(f'{BASE_URL}?cveId={cve_id}', headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def extract_criteria(configurations):
    """
    Extracts and returns the criteria strings from the configurations list.
    """
    criteria_list = []
    if configurations:
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_match = node.get('cpeMatch', [])
                for cpe in cpe_match:
                    criteria = cpe.get('criteria')
                    if criteria:
                        criteria_list.append(criteria)
    
    return criteria_list



def display_cve_info(cve_info):
    """
    Display the CVE information in the terminal.
    """
    if cve_info and 'vulnerabilities' in cve_info:
        cve = cve_info['vulnerabilities'][0]['cve']
        cve_id = cve['id']
        descriptions = cve['descriptions']
        metrics = cve['metrics']
        configurations = cve['configurations']
        
        
        border = '+' + '-'*78 + '+'
        print("\n" + border)
        
        print(f"CVE ID: {cve_id}")

        for description in descriptions:
            if description['lang'] == 'en':
                print(f"Description: {description['value']}")

        if metrics:
            print("\nCVSS Metrics:")
            for metric_type, metric_values in metrics.items():
                for metric in metric_values:
                    if 'cvssData' in metric:
                        cvss_data = metric['cvssData']
                        version = cvss_data['version']
                        print(f"CVSS Version {version}:")
                        print(f"  Severity: {cvss_data.get('baseSeverity', 'N/A')}")
                        print(f"  Base Score: {cvss_data.get('baseScore', 'N/A')}")
                        print(f"  Impact Score: {metric.get('impactScore', 'N/A')}")
                        print(f"  Exploitability Score: {metric.get('exploitabilityScore', 'N/A')}")
                        print(f"  Vector: {cvss_data.get('vectorString', 'N/A')}")
            

        
        criteria_list = extract_criteria(configurations)
        if criteria_list:
            print('\nKnown Affected Software Configurations:')
            for criteria in criteria_list:
                print(f"  CPE: {criteria}")

        print(border)

    else:
        print("CVE not found or an error occurred.")
        
        
def main():
    # Prompt the user for CVE IDs
    cve_ids = input("Enter the CVE IDs you want to know about (comma-separated): ").split(',')

    # Fetch and display information for each CVE ID
    for cve_id in cve_ids:
        cve_id = cve_id.strip()  # Remove any leading/trailing whitespace
        if cve_id:
            cve_info = fetch_cve_info(cve_id)
            display_cve_info(cve_info)

if __name__ == '__main__':
    main()
