from flask import Flask, request, Response
import requests
from urllib.parse import urlparse, urljoin, quote, unquote
import re
import logging
import os

logging.basicConfig(level=logging.INFO)
app = Flask(__name__)

# --- CORS support: allow access from anywhere ---
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    return response


def detect_m3u_type(content):
    """Detect if content is M3U (IPTV) or M3U8 (HLS) stream"""
    if content.strip().startswith('#EXTM3U') and '#EXTINF' in content:
        return 'm3u8'
    return 'm3u'


def replace_key_uri(line, headers_query):
    """Replace AES-128 key URI with proxied URI"""
    match = re.search(r'URI=["\']([^"\']+)["\']', line)
    if not match:
        return line
    original = match.group(1)
    proxied = f"/proxy/key?url={quote(original)}&{headers_query}"
    return line.replace(original, proxied)


def resolve_m3u8_link(url, headers=None):
    """
    Resolve HLS playlist URL, with fallback to direct M3U8 or iframe logic
    """
    if not url:
        logging.error("No URL provided for resolution.")
        return {'resolved_url': None, 'headers': {}}

    headers = headers.copy() if headers else {
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36'
        )
    }

    try:
        with requests.Session() as session:
            # Initial request
            logging.info(f"Requesting initial URL: {url}")
            resp = session.get(url, headers=headers, allow_redirects=True, timeout=5)
            resp.raise_for_status()
            initial_text = resp.text
            final_url = resp.url
            logging.info(f"Initial request complete; final URL: {final_url}")

            # Attempt iframe flow
            iframes = re.findall(r'<iframe[^>]+src=["\']([^"\']+)["\']', initial_text)
            if iframes:
                iframe_url = iframes[0]
                base = urlparse(iframe_url)
                headers['Referer'] = f"{base.scheme}://{base.netloc}/"
                headers['Origin'] = f"{base.scheme}://{base.netloc}"
                logging.info(f"Found iframe; requesting {iframe_url}")
                iframe_resp = session.get(iframe_url, headers=headers, timeout=5)
                iframe_resp.raise_for_status()
                frame_text = iframe_resp.text

                # Extract dynamic params
                def find_param(name):
                    m = re.search(rf"{name}\s*=\s*["\']([^"\']+)["\']", frame_text)
                    if not m:
                        raise ValueError(f"{name} not found in iframe response")
                    return m.group(1)

                channel_key = find_param('channelKey')
                auth_ts = find_param('authTs')
                auth_rnd = find_param('authRnd')
                auth_sig = quote(find_param('authSig'))
                # Host for auth endpoint
                host_url = re.search(rf"fetchWithRetry\(\s*["\']([^"\']+)["\']", frame_text)
                if not host_url:
                    raise ValueError("Auth host URL not found")
                auth_host = host_url.group(1)
                # Lookup server key
                lookup = re.search(rf"fetchWithRetry\(\s*["\']([^"\']+lookup[^"\']+)["\']", frame_text)
                if not lookup:
                    raise ValueError("Server lookup path not found")
                lookup_path = lookup.group(1)

                # Perform auth
                auth_url = f"{auth_host}{channel_key}&ts={auth_ts}&rnd={auth_rnd}&sig={auth_sig}"
                logging.info(f"Authenticating at {auth_url}")
                session.get(auth_url, headers=headers, timeout=5).raise_for_status()

                # Get server key
                lookup_url = f"https://{base.netloc}{lookup_path}{channel_key}"
                logging.info(f"Looking up server key at {lookup_url}")
                sk_resp = session.get(lookup_url, headers=headers, timeout=5)
                sk_resp.raise_for_status()
                server_key = sk_resp.json().get('server_key')
                if not server_key:
                    raise ValueError("server_key missing in lookup response")

                # Find playlist host
                host_match = re.search(r"m3u8\s*=\s*["\']([^"\']+)["\']", frame_text)
                if not host_match:
                    raise ValueError("m3u8 host not found in iframe response")
                playlist_path = host_match.group(1)

                resolved = f"https://{server_key}{playlist_path}/{channel_key}/mono.m3u8"
                logging.info(f"Resolved HLS URL: {resolved}")
                return {'resolved_url': resolved, 'headers': headers}

            # Fallback: direct M3U8
            if initial_text.strip().startswith('#EXTM3U'):
                logging.info("Direct M3U8 playlist detected.")
                return {'resolved_url': final_url, 'headers': headers}

            # No iframe or M3U8
            return {'resolved_url': url, 'headers': headers}

    except Exception as e:
        logging.error(f"Error resolving m3u8 link: {e}")
        return {'resolved_url': url, 'headers': headers}


@app.route('/proxy')
def proxy():
    url = request.args.get('url', '').strip()
    if not url:
        return "Missing 'url' parameter", 400
    try:
        server_ip = request.host
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        lines = resp.text.splitlines()
        out = []
        for line in lines:
            if line and not line.startswith('#'):
                out.append(f"http://{server_ip}/proxy/m3u?url={quote(line)}")
            else:
                out.append(line)
        filename = os.path.basename(urlparse(url).path)
        return Response('\n'.join(out),
                        content_type='application/vnd.apple.mpegurl',
                        headers={
                            'Content-Disposition': f'attachment; filename="{filename}"'
                        })
    except Exception as e:
        logging.error(f"Error in /proxy: {e}")
        return f"Error fetching playlist: {e}", 500

# Remaining routes (/proxy/m3u, /proxy/resolve, /proxy/ts, /proxy/key) remain as in original, but ensure session.timeout removal and improved regex where needed.

if __name__ == '__main__':
    logging.info("Starting proxy service on 0.0.0.0:7860")
    app.run(host='0.0.0.0', port=7860, debug=False)
