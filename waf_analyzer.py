import requests
import argparse
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# WAF detection signatures
WAF_SIGNATURES = {
    "Cloudflare": [
        "cloudflare",
        "cf-ray",
        "cf-request-id",
        "cloudflare-nginx"
    ],
    "AWS WAF": [
        "awselb",
        "awselb/2.0",
        "x-amz-cf-id",
        "x-amz-cf-pop"
    ],
    "Akamai": [
        "akamai",
        "akamai-nginx",
        "akamai-gateway",
        "x-akamai-transformed"
    ],
    "Sucuri": [
        "sucuri",
        "x-sucuri-cache",
        "x-sucuri-id"
    ],
    "Imperva": [
        "imperva",
        "x-imperva",
        "x-imwaf",
        "x-imwaf-id"
    ],
    "F5": [
        "f5",
        "x-f5",
        "x-f5-bigip",
        "x-f5-icontrol"
    ],
    "ModSecurity": [
        "mod_security",
        "modsecurity",
        "x-modsecurity",
        "x-modsecurity-id"
    ],
    "Barracuda": [
        "barracuda",
        "x-barracuda",
        "x-barracuda-id"
    ],
    "Palo Alto": [
        "paloalto",
        "x-paloalto",
        "x-paloalto-id"
    ],
    "Fortinet": [
        "fortinet",
        "x-fortinet",
        "x-fortinet-id"
    ],
    "Oracle Cloud": [
        "oraclecloud",
        "x-oracle",
        "x-oracle-id"
    ],
    "Google Cloud Armor": [
        "gcp",
        "x-google",
        "x-google-id"
    ]
}

def check_waf(url, timeout=5):
    """
    Check if a given URL has a WAF by analyzing HTTP headers and response patterns.
    """
    try:
        # Add https:// if not present
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Make request with timeout
        response = requests.get(url, timeout=timeout, allow_redirects=True, 
                               headers={'User-Agent': 'WAF-Analyzer/1.0'})
        
        # Check for WAF headers
        waf_detected = []
        response_headers = response.headers
        
        # Check each WAF signature
        for waf_name, signatures in WAF_SIGNATURES.items():
            for signature in signatures:
                # Check in headers
                for header_name, header_value in response_headers.items():
                    if signature.lower() in str(header_value).lower():
                        waf_detected.append(waf_name)
                        break
                # Check in response body (for some WAFs)
                if signature.lower() in response.text.lower():
                    waf_detected.append(waf_name)
                    break
        
        # Check for common WAF error pages
        if response.status_code in [403, 406, 500, 503]:
            # Common WAF error page indicators
            waf_indicators = [
                "blocked by security",
                "access denied",
                "security check",
                "waf",
                "firewall",
                "blocked",
                "forbidden",
                "access restricted"
            ]
            
            response_lower = response.text.lower()
            for indicator in waf_indicators:
                if indicator in response_lower:
                    waf_detected.append("Generic WAF")
                    break
        
        # Remove duplicates
        waf_detected = list(set(waf_detected))
        
        return {
            "url": url,
            "status": response.status_code,
            "waf_detected": waf_detected,
            "response_time": response.elapsed.total_seconds(),
            "redirected": response.url != url
        }
        
    except requests.exceptions.RequestException as e:
        return {
            "url": url,
            "error": str(e),
            "waf_detected": [],
            "response_time": 0,
            "redirected": False
        }
    except Exception as e:
        return {
            "url": url,
            "error": f"Unexpected error: {str(e)}",
            "waf_detected": [],
            "response_time": 0,
            "redirected": False
        }

def read_subdomains_from_file(filename):
    """Read subdomains from a file."""
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading file {filename}: {e}")
        return []

def write_results_to_file(results, output_file):
    """Write results to a file."""
    try:
        with open(output_file, 'w') as f:
            f.write("URL,Status,WAF Detected,Response Time (s),Redirected\n")
            for result in results:
                waf_list = ','.join(result['waf_detected']) if result['waf_detected'] else 'None'
                f.write(f"{result['url']},{result['status']},{waf_list},{result['response_time']:.2f},{result['redirected']}\n")
        print(f"Results written to {output_file}")
    except Exception as e:
        print(f"Error writing to file {output_file}: {e}")

def main():
    parser = argparse.ArgumentParser(description="WAF Detection Tool for Subdomains")
    parser.add_argument("-i", "--input", required=True, help="Input file containing subdomains (one per line)")
    parser.add_argument("-o", "--output", help="Output file for results")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    parser.add_argument("-T", "--timeout", type=int, default=5, help="Request timeout in seconds (default: 5)")
    
    args = parser.parse_args()
    
    # Read subdomains
    subdomains = read_subdomains_from_file(args.input)
    if not subdomains:
        print("No subdomains found in input file.")
        sys.exit(1)
    
    print(f"Analyzing {len(subdomains)} subdomains...")
    
    # Process subdomains
    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        # Submit all tasks
        future_to_url = {executor.submit(check_waf, url, args.timeout): url for url in subdomains}
        
        # Collect results
        for future in as_completed(future_to_url):
            result = future.result()
            results.append(result)
            # Print progress
            if result.get('error'):
                print(f"Error for {result['url']}: {result['error']}")
            else:
                waf_str = ','.join(result['waf_detected']) if result['waf_detected'] else 'None'
                print(f"{result['url']}: Status {result['status']} | WAF: {waf_str}")
    
    # Print summary
    waf_count = sum(1 for r in results if r['waf_detected'])
    print(f"\nAnalysis complete. {waf_count} out of {len(results)} subdomains have WAF detected.")
    
    # Write results to file if specified
    if args.output:
        write_results_to_file(results, args.output)
    
    # Print detailed results
    print("\nDetailed Results:")
    print("-" * 80)
    for result in results:
        if result.get('error'):
            print(f"URL: {result['url']}")
            print(f"Error: {result['error']}")
        else:
            waf_list = ','.join(result['waf_detected']) if result['waf_detected'] else 'None'
            print(f"URL: {result['url']}")
            print(f"Status: {result['status']}")
            print(f"WAF Detected: {waf_list}")
            print(f"Response Time: {result['response_time']:.2f}s")
            print(f"Redirected: {result['redirected']}")
        print("-" * 80)

if __name__ == "__main__":
    main()
