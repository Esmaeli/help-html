#!/usr/bin/env python3
"""
Advanced Proxy Checker - Direct Socket Scanner
Auto-detects HTTP, HTTPS, SOCKS4, SOCKS5 proxies
Optimized with 5000 concurrent connections for GitHub Actions
"""

import asyncio
import aiohttp
import socket
import ipaddress
from typing import List, Tuple, Optional, Dict
from datetime import datetime
import sys

# ========== CONFIGURATION ==========
INPUT_FILE = "ips.txt"
RESULT_FILE = "result.txt"
DETAILED_RESULT_FILE = "detailed_results.txt"
MAX_CONCURRENT = 5000  # High concurrency for GitHub
CONNECTION_TIMEOUT = 3  # Seconds
PROXY_TEST_TIMEOUT = 5  # Seconds
TEST_URL = "http://www.google.com"
TEST_URL_HTTPS = "https://www.google.com"

# Port to protocol mapping (known defaults)
PORT_PROTOCOL_MAP = {
    3128: "HTTP",      # Squid default
    3129: "HTTP",      # Squid alternative
    8080: "HTTP",      # Common HTTP proxy
    8088: "HTTP",      # HTTP proxy
    8888: "HTTP",      # HTTP proxy
    80: "HTTP",        # HTTP
    443: "HTTPS",      # HTTPS
    1080: "SOCKS5",    # SOCKS default
    10808: "SOCKS5",   # SOCKS alternative
    4545: "SOCKS5",    # SOCKS port
}

PORTS = [3128, 3129, 1080, 10808, 8080, 8088, 8888, 4545, 80, 443]

# ========== IP RANGE PARSER ==========
def expand_ip_ranges() -> List[str]:
    """
    Expand CIDR ranges to individual IPs with smart limiting
    """
    ips = []
    
    try:
        with open(INPUT_FILE, 'r') as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        print(f"[*] Processing {len(lines)} IP ranges")
        
        for line in lines:
            try:
                network = ipaddress.ip_network(line, strict=False)
                # For large networks, sample to avoid too many IPs
                if network.prefixlen <= 16:  # /16 or larger
                    # Take first 1000 IPs from large ranges
                    count = 0
                    for ip in network.hosts():
                        ips.append(str(ip))
                        count += 1
                        if count >= 1000:
                            break
                else:
                    # For smaller ranges, take all
                    for ip in network.hosts():
                        ips.append(str(ip))
                        
            except Exception as e:
                print(f"  [!] Error parsing {line}: {e}")
                continue
                
    except FileNotFoundError:
        print(f"[!] Error: {INPUT_FILE} not found!")
        sys.exit(1)
    
    # Remove duplicates
    ips = list(set(ips))
    print(f"[+] Expanded to {len(ips)} unique IP addresses")
    return ips

# ========== PORT SCANNER ==========
async def scan_port(ip: str, port: int, semaphore: asyncio.Semaphore) -> Tuple[str, int, bool]:
    """
    Check if a port is open using TCP connect
    """
    async with semaphore:
        try:
            # Attempt TCP connection
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=CONNECTION_TIMEOUT
            )
            writer.close()
            await writer.wait_closed()
            return (ip, port, True)
        except:
            return (ip, port, False)

async def scan_all_ports(ips: List[str]) -> List[Tuple[str, int]]:
    """
    Scan all IPs and ports concurrently
    """
    total_checks = len(ips) * len(PORTS)
    print(f"\n[*] Starting port scan: {len(ips)} IPs × {len(PORTS)} ports = {total_checks} checks")
    print(f"[*] Concurrency: {MAX_CONCURRENT} simultaneous connections")
    print(f"[*] Timeout: {CONNECTION_TIMEOUT}s per connection")
    
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    tasks = []
    
    # Create all scan tasks
    for ip in ips:
        for port in PORTS:
            tasks.append(scan_port(ip, port, semaphore))
    
    open_ports = []
    completed = 0
    
    # Process results as they complete
    for coro in asyncio.as_completed(tasks):
        ip, port, is_open = await coro
        completed += 1
        
        if is_open:
            open_ports.append((ip, port))
            print(f"  🔓 OPEN PORT: {ip}:{port} (Progress: {completed}/{total_checks})")
        
        # Show progress every 10%
        if completed % (total_checks // 10) == 0:
            progress = (completed / total_checks) * 100
            print(f"  📊 Scan progress: {progress:.1f}% ({completed}/{total_checks}) | Found: {len(open_ports)}")
    
    print(f"\n[+] Port scan complete! Found {len(open_ports)} open ports")
    return open_ports

# ========== PROXY TESTER ==========
async def test_http_proxy(ip: str, port: int) -> bool:
    """
    Test HTTP proxy
    """
    try:
        connector = aiohttp.TCPConnector()
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(
                TEST_URL,
                proxy=f"http://{ip}:{port}",
                timeout=aiohttp.ClientTimeout(total=PROXY_TEST_TIMEOUT),
                allow_redirects=True
            ) as response:
                if response.status == 200:
                    text = await response.text()
                    if "google" in text.lower():
                        return True
    except:
        pass
    return False

async def test_https_proxy(ip: str, port: int) -> bool:
    """
    Test HTTPS proxy
    """
    try:
        connector = aiohttp.TCPConnector()
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(
                TEST_URL_HTTPS,
                proxy=f"http://{ip}:{port}",
                timeout=aiohttp.ClientTimeout(total=PROXY_TEST_TIMEOUT),
                allow_redirects=True,
                ssl=False
            ) as response:
                if response.status == 200:
                    return True
    except:
        pass
    return False

async def test_socks5_proxy(ip: str, port: int) -> bool:
    """
    Test SOCKS5 proxy
    """
    try:
        from aiohttp_socks import ProxyConnector, ProxyType
        connector = ProxyConnector(
            proxy_type=ProxyType.SOCKS5,
            host=ip,
            port=port,
            rdns=True
        )
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(
                TEST_URL,
                timeout=aiohttp.ClientTimeout(total=PROXY_TEST_TIMEOUT)
            ) as response:
                if response.status == 200:
                    text = await response.text()
                    if "google" in text.lower():
                        return True
    except:
        pass
    return False

async def test_socks4_proxy(ip: str, port: int) -> bool:
    """
    Test SOCKS4 proxy
    """
    try:
        from aiohttp_socks import ProxyConnector, ProxyType
        connector = ProxyConnector(
            proxy_type=ProxyType.SOCKS4,
            host=ip,
            port=port,
            rdns=True
        )
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(
                TEST_URL,
                timeout=aiohttp.ClientTimeout(total=PROXY_TEST_TIMEOUT)
            ) as response:
                if response.status == 200:
                    text = await response.text()
                    if "google" in text.lower():
                        return True
    except:
        pass
    return False

async def detect_proxy_type(ip: str, port: int) -> Optional[str]:
    """
    Auto-detect proxy type based on port and testing
    """
    # Try based on common port mapping first
    expected_type = PORT_PROTOCOL_MAP.get(port)
    
    if expected_type == "HTTP":
        if await test_http_proxy(ip, port):
            return "HTTP"
        if await test_https_proxy(ip, port):
            return "HTTPS"
            
    elif expected_type == "HTTPS":
        if await test_https_proxy(ip, port):
            return "HTTPS"
        if await test_http_proxy(ip, port):
            return "HTTP"
            
    elif expected_type == "SOCKS5":
        if await test_socks5_proxy(ip, port):
            return "SOCKS5"
        if await test_socks4_proxy(ip, port):
            return "SOCKS4"
    
    else:  # Unknown, test all
        if await test_http_proxy(ip, port):
            return "HTTP"
        if await test_https_proxy(ip, port):
            return "HTTPS"
        if await test_socks5_proxy(ip, port):
            return "SOCKS5"
        if await test_socks4_proxy(ip, port):
            return "SOCKS4"
    
    return None

async def test_proxy(ip: str, port: int, semaphore: asyncio.Semaphore) -> Tuple[str, int, Optional[str]]:
    """
    Test a single proxy with protocol detection
    """
    async with semaphore:
        protocol = await detect_proxy_type(ip, port)
        return (ip, port, protocol)

async def test_all_proxies(open_ports: List[Tuple[str, int]]) -> List[Tuple[str, int, str]]:
    """
    Test all open ports as proxies with high concurrency
    """
    print(f"\n[*] Testing {len(open_ports)} proxies for Google access...")
    print(f"[*] Concurrency: {MAX_CONCURRENT} parallel tests")
    print(f"[*] Timeout: {PROXY_TEST_TIMEOUT}s per test\n")
    
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    tasks = [test_proxy(ip, port, semaphore) for ip, port in open_ports]
    
    working_proxies = []
    completed = 0
    total = len(tasks)
    
    print("-" * 70)
    
    for coro in asyncio.as_completed(tasks):
        ip, port, protocol = await coro
        completed += 1
        
        if protocol:
            working_proxies.append((ip, port, protocol))
            print(f"  ✅ WORKING: {ip}:{port} | Type: {protocol} | Found: {len(working_proxies)}")
        else:
            # Show every 100 failures to reduce noise
            if completed % 100 == 0:
                print(f"  ⏳ Progress: {completed}/{total} | Working: {len(working_proxies)}")
    
    print("-" * 70)
    print(f"\n[+] Proxy testing complete! Found {len(working_proxies)} working proxies")
    
    return working_proxies

# ========== RESULT SAVING ==========
def save_results(proxies: List[Tuple[str, int, str]]):
    """
    Save results in multiple formats
    """
    # Simple format (ip:port)
    with open(RESULT_FILE, 'w') as f:
        for ip, port, _ in proxies:
            f.write(f"{ip}:{port}\n")
    
    # Detailed format with protocol
    with open(DETAILED_RESULT_FILE, 'w') as f:
        f.write("# Working Proxies - Format: IP:PORT|PROTOCOL\n")
        f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("#" + "="*60 + "\n\n")
        for ip, port, protocol in proxies:
            f.write(f"{ip}:{port}|{protocol}\n")
    
    # Statistics by protocol
    protocol_stats = {}
    for _, _, protocol in proxies:
        protocol_stats[protocol] = protocol_stats.get(protocol, 0) + 1
    
    print(f"\n📊 PROXY DISTRIBUTION:")
    for proto, count in sorted(protocol_stats.items()):
        print(f"  {proto}: {count} proxies")
    
    print(f"\n💾 RESULTS SAVED:")
    print(f"  - {RESULT_FILE}: Simple IP:PORT format")
    print(f"  - {DETAILED_RESULT_FILE}: Detailed with protocol info")

# ========== MAIN ==========
async def main():
    """
    Main execution
    """
    start_time = datetime.now()
    
    print("="*70)
    print("🚀 ADVANCED PROXY CHECKER - Auto Protocol Detection")
    print(f"📅 Start Time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"⚡ Configuration: {MAX_CONCURRENT} concurrent workers")
    print(f"🔧 Testing {len(PORTS)} ports per IP")
    print("="*70)
    
    # Step 1: Expand IP ranges
    ips = expand_ip_ranges()
    
    if not ips:
        print("[!] No IP addresses to scan. Check your ips.txt file.")
        sys.exit(1)
    
    # Step 2: Scan for open ports
    open_ports = await scan_all_ports(ips)
    
    if not open_ports:
        print("[!] No open ports found. Exiting.")
        sys.exit(0)
    
    # Step 3: Test proxies
    working_proxies = await test_all_proxies(open_ports)
    
    # Step 4: Save results
    if working_proxies:
        save_results(working_proxies)
    else:
        print("\n[!] No working proxies found matching the criteria.")
        # Create empty result files
        open(RESULT_FILE, 'w').close()
        open(DETAILED_RESULT_FILE, 'w').close()
    
    # Summary
    end_time = datetime.now()
    duration = end_time - start_time
    
    print("\n" + "="*70)
    print("📈 FINAL SUMMARY")
    print(f"  Total IPs scanned: {len(ips)}")
    print(f"  Open ports found: {len(open_ports)}")
    print(f"  Working proxies: {len(working_proxies)}")
    print(f"  Success rate: {(len(working_proxies)/len(open_ports)*100):.2f}%" if open_ports else "  Success rate: 0%")
    print(f"  Total duration: {duration}")
    print(f"  Average speed: {len(open_ports)/duration.total_seconds():.2f} proxies/second")
    print("="*70)

if __name__ == "__main__":
    # Install aiohttp-socks if needed
    try:
        import aiohttp_socks
    except ImportError:
        print("[*] Installing aiohttp-socks for SOCKS support...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "aiohttp-socks"])
        import aiohttp_socks
    
    asyncio.run(main())
