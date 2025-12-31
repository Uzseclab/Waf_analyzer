# Waf_analyzer
### Features:

1. **Multi-threaded Analysis**: Processes multiple subdomains concurrently for faster results
2. **Comprehensive WAF Detection**:
   - Checks HTTP headers for WAF-specific indicators
   - Analyzes response body content
   - Detects common WAF error pages
   - Supports 13 major WAF vendors
3. **Detailed Output**:
   - Status codes
   - Response times
   - Redirect information
   - WAF vendor detection
4. **File I/O Support**:
   - Read subdomains from text files
   - Export results to CSV format
5. **Error Handling**:
   - Handles timeouts gracefully
   - Reports connection errors
   - Continues processing despite individual failures

### Usage:

1. **Save the script** as `waf_analyzer.py`

2. **Create a subdomain list** (e.g., `subdomains.txt`):
   ```
   example.com
   api.example.com
   blog.example.com
   shop.example.com
   ```

3. **Run the analysis**:
   ```bash
   python waf_analyzer.py -i subdomains.txt -o results.csv -t 20 -T 10
   ```

### Command-line Options:
- `-i, --input`: Required input file with subdomains (one per line)
- `-o, --output`: Optional output file for results (CSV format)
- `-t, --threads`: Number of concurrent threads (default: 10)
- `-T, --timeout`: Request timeout in seconds (default: 5)

### Example Output:
```
example.com: Status 200 | WAF: Cloudflare
api.example.com: Status 403 | WAF: Imperva
blog.example.com: Status 200 | WAF: None

Analysis complete. 1 out of 3 subdomains have WAF detected.
Results written to results.csv
```

### Requirements:
```bash
pip install requests
```
