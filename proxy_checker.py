#!/usr/bin/env python3
"""
Proxy Checker without masscan - Direct socket scanning
Optimized for GitHub Actions
"""

import asyncio
import aiohttp
import socket
import ipaddress
from typing import List, Tuple, Optional
from datetime import datetime
import sys

# Configuration
INPUT_FILE = "ips.txt"
RESULT_FILE = "result.txt"
DETAILED_RESULT_FILE = "detailed_results.txt"
# Common proxy ports
PORTS = [3128, 3129, 1080, 10808, 8080, 8088, 8888, 4545, 80, 443, 8118, 9060, 9050, 4145, 2128]
MAX_CONCURRENT_SCAN = 1000
MAX_CONCURRENT_PROXY_TEST = 500
TIMEOUT = 3
TEST_URL = "http://www.google.com"

def expand_ip_ranges() -> List[str]:
    """
    Expand CIDR ranges to individual IPs (limited to /24 for performance)
    """
    ips = []
    try:
        with open(INPUT_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    # For large subnets, only take first 256 IPs to avoid explosion
                    if '/16' in line or '/12' in line or '/14' in line:
                        # For large ranges, convert to /24
                        network = ipaddress.ip_network(line, strict=False)
                        # Take first 256 IPs from the range
                        for i, ip in enumerate(network.hosts()):
                            if i >= 256:
                                break
                            ips.append(str(ip))
                    else:
                        # For /24 or smaller, expand all
                        network = ipaddress.ip_network(line, strict=False)
                        # Limit to 256 IPs per range
                        for i, ip in enumerate(network.hosts()):
                            if i >= 256:
                                break
                            ips.append(str(ip))
                except Exception as e:
                    print(f"Error parsing {line}: {e}")
                    continue
    except FileNotFoundError:
        print(f"Error: {INPUT_FILE} not found")
        sys.exit(1)
    
    print(f"Expanded {len(ips)} IP addresses to scan")
    return ips

async def check_port(ip: str, port: int, semaphore: asyncio.Semaphore) -> Tuple[str, int, bool]:
    """
    Check if a specific port is open using TCP connect
    """
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=TIMEOUT
            )
            writer.close()
            await writer.wait_closed()
            return (ip, port, True)
        except:
            return (ip, port, False)

async def scan_ports(ips: List[str]) -> List[Tuple[str, int]]:
    """
    Scan all IPs and ports for open ports
    """
    print(f"\n[*] Scanning {len(ips)} IPs on {len(PORTS)} ports...")
    print(f"[*] Total checks: {len(ips) * len(PORTS)}")
    
    open_ports = []
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCAN)
    tasks = []
    
    for ip in ips:
        for port in PORTS:
            tasks.append(check_port(ip, port, semaphore))
    
    # Process in batches to avoid memory issues
    batch_size = 5000
    total_tasks = len(tasks)
    
    for i in range(0, total_tasks, batch_size):
        batch = tasks[i:i+batch_size]
        results = await asyncio.gather(*batch)
        for ip, port, is_open in results:
            if is_open:
                open_ports.append((ip, port))
                print(f"  ✅ Found open port: {ip}:{port}")
        
        print(f"  Progress: {min(i+batch_size, total_tasks)}/{total_tasks}")
    
    print(f"[+] Found {len(open_ports)} open ports")
    return open_ports

async def check_proxy(ip: str, port: int) -> Optional[str]:
    """
    Test if IP:port works as proxy for Google
    Returns protocol or None
    """
    # Try HTTP
    try:
        connector = aiohttp.TCPConnector()
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(
                TEST_URL,
                proxy=f"http://{ip}:{port}",
                timeout=aiohttp.ClientTimeout(total=TIMEOUT),
                allow_redirects=True
            ) as response:
                if response.status == 200:
                    text = await response.text()
                    if "google" in text.lower():
                        return "HTTP"
    except:
        pass
    
    # Try HTTPS
    try:
        connector = aiohttp.TCPConnector()
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(
                "https://www.google.com",
                proxy=f"http://{ip}:{port}",
                timeout=aiohttp.ClientTimeout(total=TIMEOUT),
                allow_redirects=True,
                ssl=False
            ) as response:
                if response.status == 200:
                    return "HTTPS"
    except:
        pass
    
    # Try SOCKS5
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
                timeout=aiohttp.ClientTimeout(total=TIMEOUT)
            ) as response:
                if response.status == 200:
                    return "SOCKS5"
    except:
        pass
    
    return None

async def test_proxies(open_ports: List[Tuple[str, int]]):
    """
    Test all open ports as proxies
    """
    print(f"\n[*] Testing {len(open_ports)} proxies...")
    
    successful = []
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_PROXY_TEST)
    
    async def test_one(ip, port):
        async with semaphore:
            protocol = await check_proxy(ip, port)
            return (ip, port, protocol)
    
    tasks = [test_one(ip, port) for ip, port in open_ports]
    
    for i, coro in enumerate(asyncio.as_completed(tasks)):
        ip, port, protocol = await coro
        if protocol:
            successful.append((ip, port, protocol))
            print(f"  ✅ WORKING: {ip}:{port} [{protocol}] (Total: {len(successful)})")
        
        if (i + 1) % 100 == 0:
            print(f"  Progress: {i+1}/{len(open_ports)}")
    
    return successful

def save_results(results):
    """Save results to files"""
    with open(RESULT_FILE, 'w') as f:
        for ip, port, _ in results:
            f.write(f"{ip}:{port}\n")
    
    with open(DETAILED_RESULT_FILE, 'w') as f:
        f.write("# IP:PORT|PROTOCOL\n")
        for ip, port, protocol in results:
            f.write(f"{ip}:{port}|{protocol}\n")
    
    print(f"\n[+] Results saved:")
    print(f"    - {RESULT_FILE}: {len(results)} proxies")
    print(f"    - {DETAILED_RESULT_FILE}: detailed with protocols")

async def main():
    print("="*60)
    print("PROXY CHECKER - Direct Socket Scan (No masscan)")
    print(f"Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)
    
    # Expand IP ranges
    ips = expand_ip_ranges()
    
    if not ips:
        print("No IPs to scan")
        sys.exit(1)
    
    # Scan for open ports
    open_ports = await scan_ports(ips)
    
    if not open_ports:
        print("No open ports found")
        sys.exit(0)
    
    # Test proxies
    working_proxies = await test_proxies(open_ports)
    
    # Save results
    if working_proxies:
        save_results(working_proxies)
    else:
        print("No working proxies found")
    
    duration = datetime.now() - datetime.strptime("2026-05-02 07:20:00", "%Y-%m-%d %H:%M:%S")
    print(f"\nTotal time: {duration}")
    print("="*60)

if __name__ == "__main__":
    asyncio.run(main())
