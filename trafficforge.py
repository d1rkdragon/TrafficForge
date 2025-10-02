
import os
import time
import argparse
import dpkt
import sys
import requests
from urllib.parse import urlparse

EXTS = ('.pcap', '.pcapng')

def open_pcap(path):
    f = open(path, 'rb')
    try:
        return dpkt.pcap.Reader(f)
    except (dpkt.dpkt.NeedData, ValueError):
        f.seek(0)
        try:
            return dpkt.pcapng.Reader(f)
        except Exception:
            f.close()
            raise

def ts_to_str(ts):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))

def gather_files_from_dir(dir_path):
    return [
        os.path.join(dir_path, f)
        for f in os.listdir(dir_path)
        if os.path.isfile(os.path.join(dir_path, f)) and f.lower().endswith(EXTS)
    ]

def normalize_proxy_arg(proxy_arg):
    if not proxy_arg:
        return None
    parsed = urlparse(proxy_arg)
    if parsed.scheme:
        return proxy_arg
    return f"http://{proxy_arg}"

def extract_http_requests(path, max_requests=None):
    out = []
    try:
        r = open_pcap(path)
    except Exception as e:
        print(f"[!] Failed to open {path}: {e}")
        return out

    for ts, buf in r:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue
            ip = eth.data
            if not isinstance(ip.data, dpkt.tcp.TCP):
                continue
            payload = ip.data.data
            if not payload:
                continue
            if payload.startswith((b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS')):
                try:
                    req = dpkt.http.Request(payload)
                except (dpkt.UnpackError, ValueError):
                    continue
                headers = dict(req.headers)
                host = headers.get('host')
                scheme = 'http'
                if host and host.endswith(':443'):
                    scheme = 'https'
                url = f"{scheme}://{host}{req.uri}" if host else f"http://{getattr(ip, 'dst', '0.0.0.0')}{req.uri}"
                out.append({
                    'ts': ts,
                    'method': req.method,
                    'uri': req.uri,
                    'version': req.version,
                    'headers': headers,
                    'body': req.body or b'',
                    'host': host,
                    'url': url
                })
                if max_requests and len(out) >= max_requests:
                    break
        except Exception:
            continue
    return out

def send_request_via_proxy(req_obj, proxy_url, dry_run=False, timeout=15):
    method = req_obj['method']
    url = req_obj['url']
    headers = req_obj['headers'].copy()
    body = req_obj['body']

    if 'host' not in {k.lower() for k in headers} and req_obj.get('host'):
        headers['Host'] = req_obj['host']
    headers['Connection'] = 'close'

    proxies = {'http': proxy_url, 'https': proxy_url} if proxy_url else None

    if dry_run:
        print("---- DRY RUN REQUEST ----")
        print(f"{method} {url}")
        for k, v in headers.items():
            print(f"{k}: {v}")
        if body:
            print()
            print(body[:500].decode(errors='replace') + ("..." if len(body) > 500 else ""))
        print("-------------------------")
        return None

    try:
        r = requests.request(method, url, headers=headers, data=body, proxies=proxies, timeout=timeout, allow_redirects=False)
        return r
    except Exception as e:
        print(f"[!] Request failed: {e}")
        return None

def replay_requests_list(reqs, proxy_arg, speed=1.0, dry_run=False):
    if not reqs:
        print("[*] No HTTP requests to replay.")
        return
    proxy_url = normalize_proxy_arg(proxy_arg) if proxy_arg else None
    print(f"[*] Replaying {len(reqs)} request(s) via: {proxy_url if proxy_url else 'direct'}")
    start_ts = reqs[0]['ts']
    last_ts = start_ts
    for idx, r in enumerate(reqs, start=1):
        wait = (r['ts'] - last_ts) / speed if speed and r['ts'] >= last_ts else 0
        if wait > 0:
            time.sleep(wait)
        last_ts = r['ts']
        print(f"[{idx}/{len(reqs)}] Sending: {r['method']} {r['url']}")
        resp = send_request_via_proxy(r, proxy_url, dry_run=dry_run)
        if dry_run:
            continue
        if resp is None:
            print("   -> failed")
        else:
            body_preview = resp.text[:200].replace('\n', '\\n') if resp.text else ''
            print(f"   -> {resp.status_code} {resp.reason} (len={len(resp.content)}) preview='{body_preview}'")

def summarize_pcap(path, max_examples=5):
    try:
        r = open_pcap(path)
    except Exception as e:
        print(f"  [!] Failed to open {os.path.basename(path)}: {e}")
        return [], {}

    total = 0
    first_ts = None
    last_ts = None
    counts = {'tcp':0, 'udp':0, 'http':0, 'dns':0}
    http_examples = []
    dns_examples = []

    for ts, buf in r:
        total += 1
        if first_ts is None:
            first_ts = ts
        last_ts = ts
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue
            ip = eth.data
            if isinstance(ip.data, dpkt.tcp.TCP):
                counts['tcp'] += 1
                payload = ip.data.data
                if not payload:
                    continue
                try:
                    if payload.startswith((b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS')):
                        req = dpkt.http.Request(payload)
                        counts['http'] += 1
                        if len(http_examples) < max_examples:
                            req_str = f"{req.method} {req.uri} {req.version}\n"
                            for k, v in req.headers.items():
                                req_str += f"{k}: {v}\n"
                            if req.body:
                                req_str += f"\nBody: {req.body[:100].decode(errors='replace')}..."
                            http_examples.append(req_str.strip())
                    elif payload.startswith(b'HTTP/'):
                        res = dpkt.http.Response(payload)
                        counts['http'] += 1
                        if len(http_examples) < max_examples:
                            res_str = f"HTTP/{res.version} {res.status} {res.reason}\n"
                            for k, v in res.headers.items():
                                res_str += f"{k}: {v}\n"
                            if res.body:
                                res_str += f"\nBody: {res.body[:100].decode(errors='replace')}..."
                            http_examples.append(res_str.strip())
                except (dpkt.UnpackError, ValueError):
                    pass
            elif isinstance(ip.data, dpkt.udp.UDP):
                counts['udp'] += 1
                payload = ip.data.data
                if payload:
                    try:
                        dns = dpkt.dns.DNS(payload)
                        if dns.qr == dpkt.dns.DNS_Q and dns.qd:
                            counts['dns'] += 1
                            if len(dns_examples) < max_examples:
                                qnames = [qd.name for qd in dns.qd]
                                dns_examples.append(','.join(qnames))
                    except (dpkt.dpkt.NeedData, Exception):
                        pass
        except Exception:
            continue

    name = os.path.basename(path)
    print(f"\nFile: {name}")
    print(f"  Total packets: {total}")
    if first_ts:
        print(f"  First ts: {ts_to_str(first_ts)}")
        print(f"  Last  ts: {ts_to_str(last_ts)}")
    print(f"  TCP: {counts['tcp']}, UDP: {counts['udp']}, HTTP: {counts['http']}, DNS: {counts['dns']}")
    if http_examples:
        print("  HTTP examples (requests/responses):")
        for x in http_examples:
            print("    --- HTTP Message ---")
            print("    " + x.replace("\n", "\n    "))
    if dns_examples:
        print("  DNS examples:")
        for x in dns_examples:
            print(f"    - {x}")
    meta = {'total': total, 'first_ts': first_ts, 'last_ts': last_ts, 'counts': counts}
    return http_examples, meta

def main():
    parser = argparse.ArgumentParser(description="pcap summarizer + proxy replay")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', '--pcap', help='Single pcap file to process')
    group.add_argument('-D', '--dir', help='Directory containing pcap files')
    parser.add_argument('-p', '--proxy', help='Proxy to send reconstructed requests through (e.g. localhost:8000 or http://127.0.0.1:8080)')
    parser.add_argument('--dry-run', action='store_true', help='Print reconstructed requests instead of sending')
    parser.add_argument('--speed', type=float, default=1.0, help='Timing scale factor for replay (1.0 = original speed)')
    parser.add_argument('--max-req', type=int, default=None, help='Maximum requests to replay per file (for testing)')
    args = parser.parse_args()

    # validate targets
    if args.pcap:
        if not os.path.isfile(args.pcap):
            print(f"[!] File does not exist: {args.pcap}")
            sys.exit(1)
        if not args.pcap.lower().endswith(EXTS):
            print(f"[!] Not a valid pcap: {args.pcap}")
            sys.exit(1)
        targets = [args.pcap]
    else:
        if not os.path.isdir(args.dir):
            print(f"[!] Directory does not exist: {args.dir}")
            sys.exit(1)
        targets = gather_files_from_dir(args.dir)
        if not targets:
            print("[!] No pcap files found in directory.")
            sys.exit(0)

    proxy_arg = normalize_proxy_arg(args.proxy) if args.proxy else None
    if proxy_arg:
        print(f"[*] Proxy provided: {proxy_arg}")

    for t in targets:
        print(f"\nProcessing file: {t}")
        summarize_pcap(t, max_examples=5)  # show summary
        reqs = extract_http_requests(t, max_requests=args.max_req)
        if not reqs:
            print("[*] No HTTP requests extracted for replay.")
            continue
        replay_requests_list(reqs, proxy_arg, speed=args.speed, dry_run=args.dry_run)

if __name__ == '__main__':
    main()
