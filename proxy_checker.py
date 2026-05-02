#!/usr/bin/env python3
"""
Advanced Proxy Checker - Auto detects HTTP, HTTPS, SOCKS4, SOCKS5
Supports high concurrency for GitHub Actions
"""

import asyncio
import aiohttp
import subprocess
import sys
import re
from typing import List, Tuple, Set, Dict, Optional
from datetime import datetime
from aiohttp_socks import ProxyConnector, ProxyType
import socket

# Configuration
INPUT_FILE = "ips.txt"
MASSCAN_OUTPUT = "common_ports.txt"
RESULT_FILE = "result.txt"
DETAILED_RESULT_FILE = "detailed_results.txt"
PORTS = [3128, 3129, 1080, 10808, 8080, 8088, 8888, 4545, 80, 443]
RATE = 5000
TIMEOUT = 5  # Reduced for higher throughput
TEST_URL = "http://www.google.com"
TEST_URL_HTTPS = "https://www.google.com"
MAX_CONCURRENT = 1000  # High concurrency for GitHub's fast runners

def run_masscan() -> List[Tuple[str, int]]:
    """
    Run masscan to find open ports from ips.txt
    Returns list of (ip, port) tuples
    """
    print(f"[*] Starting masscan with rate={RATE}")
    print(f"[*] Scanning {len(PORTS)} ports on targets from {INPUT_FILE}")
    
    # Build port list string
    ports_str = ",".join(map(str, PORTS))
    
    # Masscan command - optimized for speed
    cmd = [
        "masscan",
        "-iL", INPUT_FILE,
        "-p", ports_str,
        f"--rate={RATE}",
        "--wait=0",  # Don't wait for responses
        "-oL", MASSCAN_OUTPUT
    ]
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
        print(f"[+] Masscan completed. Output saved to {MASSCAN_OUTPUT}")
    except subprocess.CalledProcessError as e:
        print(f"[-] Masscan failed: {e.stderr}")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("[-] Masscan timeout after 5 minutes")
        sys.exit(1)
    except FileNotFoundError:
        print("[-] masscan not found. Please install masscan first.")
        sys.exit(1)
    
    # Parse masscan output - optimized parsing
    open_ports = []
    try:
        with open(MASSCAN_OUTPUT, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith("open"):
                    parts = line.split()
                    if len(parts) >= 4:
                        port = int(parts[2])
                        ip = parts[3]
                        open_ports.append((ip, port))
    except FileNotFoundError:
        print(f"[-] {MASSCAN_OUTPUT} not found")
        sys.exit(1)
    
    print(f"[+] Found {len(open_ports)} open ports")
    return open_ports

async def detect_proxy_type(ip: str, port: int) -> Optional[str]:
    """
    Detect proxy type: HTTP, HTTPS, SOCKS4, SOCKS5
    Returns protocol type or None if not working
    """
    # Test HTTP proxy first (most common)
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
    
    # Test HTTPS proxy
    try:
        connector = aiohttp.TCPConnector()
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(
                TEST_URL_HTTPS,
                proxy=f"http://{ip}:{port}",
                timeout=aiohttp.ClientTimeout(total=TIMEOUT),
                allow_redirects=True,
                ssl=False
            ) as response:
                if response.status == 200:
                    text = await response.text()
                    if "google" in text.lower():
                        return "HTTPS"
    except:
        pass
    
    # Test SOCKS5 proxy (using aiohttp_socks)
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
                    text = await response.text()
                    if "google" in text.lower():
                        return "SOCKS5"
    except:
        pass
    
    # Test SOCKS4 proxy
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
                timeout=aiohttp.ClientTimeout(total=TIMEOUT)
            ) as response:
                if response.status == 200:
                    text = await response.text()
                    if "google" in text.lower():
                        return "SOCKS4"
    except:
        pass
    
    return None

async def check_proxy_advanced(semaphore: asyncio.Semaphore, ip: str, port: int) -> Tuple[str, int, Optional[str]]:
    """
    Check proxy with protocol auto-detection
    Returns (ip, port, protocol_type) where protocol_type is None if failed
    """
    async with semaphore:
        protocol = await detect_proxy_type(ip, port)
        return (ip, port, protocol)

def save_results(results: List[Tuple[str, int, str]]):
    """
    Save results in multiple formats
    """
    # Simple format (ip:port)
    with open(RESULT_FILE, 'w') as f:
        for ip, port, protocol in results:
            f.write(f"{ip}:{port}\n")
    
    # Detailed format with protocol
    with open(DETAILED_RESULT_FILE, 'w') as f:
        f.write("# Format: IP:PORT|PROTOCOL\n")
        f.write("# Protocols: HTTP, HTTPS, SOCKS4, SOCKS5\n")
        f.write("# " + "="*50 + "\n\n")
        for ip, port, protocol in results:
            f.write(f"{ip}:{port}|{protocol}\n")
    
    # Group by protocol
    protocol_stats = {}
    for _, _, protocol in results:
        protocol_stats[protocol] = protocol_stats.get(protocol, 0) + 1
    
    print("\n📊 Results by protocol:")
    for proto, count in protocol_stats.items():
        print(f"   {proto}: {count} proxies")

async def test_proxies_batch(open_ports: List[Tuple[str, int]]):
    """
    Test all proxies with high concurrency
    """
    print(f"\n[*] Testing {len(open_ports)} proxies with auto-protocol detection...")
    print(f"[*] Concurrency: {MAX_CONCURRENT} simultaneous checks")
    print("[*] Live results will appear below:\n")
    print("="*70)
    
    successful_results = []
    total = len(open_ports)
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    
    # Create tasks for all proxies
    tasks = [check_proxy_advanced(semaphore, ip, port) for ip, port in open_ports]
    
    # Track progress
    completed = 0
    successful = 0
    
    # Process as they complete
    for future in asyncio.as_completed(tasks):
        ip, port, protocol = await future
        completed += 1
        
        if protocol:
            successful += 1
            successful_results.append((ip, port, protocol))
            # Live output with color indicators
            print(f"✅ WORKING: {ip}:{port} | Protocol: {protocol} | Progress: {completed}/{total} ({successful} found)")
        else:
            # Show progress even for failures
            if completed % 100 == 0 or completed == total:
                print(f"⏳ Progress: {completed}/{total} | Working: {successful}")
    
    print("="*70)
    print(f"\n✅ Scan complete!")
    print(f"📈 Total working proxies: {successful}/{total}")
    
    if successful_results:
        save_results(successful_results)
        print(f"\n💾 Results saved to:")
        print(f"   - {RESULT_FILE} (simple format: ip:port)")
        print(f"   - {DETAILED_RESULT_FILE} (detailed with protocol)")
    
    return successful_results

async def quick_port_scan(open_ports: List[Tuple[str, int]]) -> List[Tuple[str, int]]:
    """
    Quick TCP connect scan to filter dead ports before proxy testing
    Can increase speed by 2-3x
    """
    print(f"\n[*] Quick TCP scan to filter dead ports...")
    
    async def is_port_open(ip: str, port: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=1
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False
    
    semaphore = asyncio.Semaphore(500)  # High concurrency for TCP scan
    tasks = []
    
    for ip, port in open_ports:
        async def check(sem, ip, port):
            async with sem:
                return (ip, port, await is_port_open(ip, port))
        tasks.append(check(semaphore, ip, port))
    
    results = await asyncio.gather(*tasks)
    filtered = [(ip, port) for ip, port, is_open in results if is_open]
    
    removed = len(open_ports) - len(filtered)
    print(f"[+] TCP scan complete: {len(filtered)} live ports (removed {removed} dead ports)")
    
    return filtered

async def main():
    """Main execution function with optimizations"""
    start_time = datetime.now()
    print("="*70)
    print("🚀 ADVANCED PROXY CHECKER - Auto Protocol Detection")
    print(f"📅 Start time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"⚡ GitHub Optimized - High Concurrency Mode")
    print("="*70)
    
    # Step 1: Run masscan to find open ports
    open_ports = run_masscan()
    
    if not open_ports:
        print("❌ No open ports found. Exiting.")
        sys.exit(0)
    
    # Step 2: Optional - Quick TCP scan to filter (can be disabled for speed)
    # live_ports = await quick_port_scan(open_ports)
    live_ports = open_ports  # Skip TCP scan for maximum speed
    
    # Step 3: Test each proxy with protocol detection
    successful = await test_proxies_batch(live_ports)
    
    end_time = datetime.now()
    duration = end_time - start_time
    
    print(f"\n⏱️  Total duration: {duration}")
    print(f"🚀 Average speed: {len(open_ports)/duration.total_seconds():.1f} proxies/second")
    print("="*70)

if __name__ == "__main__":
    # Install additional dependency for SOCKS support
    try:
        import aiohttp_socks
    except ImportError:
        print("[*] Installing aiohttp_socks for SOCKS support...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "aiohttp-socks"])
        import aiohttp_socks
    
    asyncio.run(main())
