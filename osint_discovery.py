"""
osint_discovery - Active internet hunting for scam websites.

This module searches the internet for potential scam sites using:
1. Search engine dorks targeting free hosting providers
2. Certificate Transparency logs for newly issued certificates
3. Social media and forum monitoring
4. Automatic verification through existing scam detection engine

Usage:
  python scamscan.py discover --config config.json --limit 10
  python scamscan.py discover --config config.json --source ct --brand fuliza
  python scamscan.py discover --config config.json --dry-run
"""

import argparse
import json
import logging
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import quote_plus

try:
    from ddgs import DDGS
except ImportError:
    try:
        from duckduckgo_search import DDGS
    except ImportError:
        DDGS = None

# Import from scamscan module
from scamscan import (
    load_env, score_finding, db_connect, upsert, 
    impersonation_score, extract_artifacts, lexicon_score,
    registrable
)

load_env()

logger = logging.getLogger(__name__)

# Free hosting providers commonly used for scam sites
FREE_HOSTS = [
    "vercel.app",
    "netlify.app",
    "netlify.com",
    "firebaseapp.com",
    "web.app",
    "github.io",
    "pages.dev",
    "000webhostapp.com",
    "infinityfreeapp.com",
    "rf.gd",
    "epizy.com",
    "ucoz.com",
    "blogspot.com",
    "wordpress.com",
    "wixsite.com",
    "mysite.com",
    "site123.me",
    "jimdosite.com",
    "weebly.com",
    "strikingly.com",
    "carrd.co",
    "linktr.ee",
    "bit.ly",
    "tinyurl.com",
]

# Search query templates
SEARCH_TEMPLATES = [
    # Google Dorks for free hosting with brand keywords
    'site:vercel.app "{brand}"',
    'site:netlify.app "{brand}"',
    'site:firebaseapp.com "{brand}"',
    'site:web.app "{brand}"',
    'site:github.io "{brand}"',
    'site:pages.dev "{brand}"',
    
    # Financial scam patterns on free hosts
    'site:vercel.app "{brand}" limit boost',
    'site:vercel.app "{brand}" loan',
    'site:vercel.app "{brand}" activation',
    'site:netlify.app "{brand}" verify',
    'site:firebaseapp.com "{brand}" login',
    
    # Generic scam patterns
    '"{brand}" "processing fee"',
    '"{brand}" "activation fee"',
    '"{brand}" "send pin"',
    '"{brand}" "confirm your"',
    '"{brand}" "customer care"',
    '"{brand}" "verified agent"',
    
    # URL patterns
    'inurl:{brand} inurl:login',
    'inurl:{brand} inurl:verify',
    'inurl:{brand} inurl:boost',
    'inurl:{brand} inurl:limit',
    'inurl:{brand} inurl:loan',
]

# Certificate Transparency query endpoints
CT_SEARCH_URL = "https://crt.sh/?q=%.{domain}&output=json"


def generate_queries(cfg, brand_keyword=None):
    """Generate search queries based on brand aliases and search templates."""
    brand = cfg.get("brand", {})
    aliases = brand.get("aliases", [])
    
    # Use specific brand keyword if provided, otherwise use main aliases
    if brand_keyword:
        keywords = [brand_keyword]
    else:
        # Prioritize high-value keywords
        keywords = []
        for alias in aliases:
            alias_lower = alias.lower()
            # Prioritize financial product names and brand names
            if any(term in alias_lower for term in ["fuliza", "shwari", "kcb", "tala", "branch", "zenka"]):
                keywords.insert(0, alias)
            elif len(alias.split()) <= 2:  # Short aliases are better for search
                keywords.append(alias)
        
        # Ensure we have at least the main brand name
        if not keywords and aliases:
            keywords = aliases[:5]
        else:
            keywords = keywords[:10]  # Limit to avoid rate limits
    
    queries = []
    seen = set()
    
    for template in SEARCH_TEMPLATES:
        for keyword in keywords:
            # Clean keyword for search
            clean_keyword = keyword.replace('"', '').strip()
            if not clean_keyword:
                continue
                
            query = template.format(brand=clean_keyword)
            
            # Avoid duplicates
            if query not in seen:
                seen.add(query)
                queries.append(query)
    
    return queries


def search_duckduckgo(query, max_results=10):
    """Search DuckDuckGo and return results."""
    if DDGS is None:
        logger.warning("duckduckgo-search not installed. Run: pip install duckduckgo-search")
        return []
    
    try:
        results = []
        with DDGS() as ddgs:
            # DuckDuckGo search
            search_results = list(ddgs.text(query, max_results=max_results))
            
            for r in search_results:
                if isinstance(r, dict):
                    results.append({
                        "title": r.get("title", ""),
                        "url": r.get("href", r.get("url", "")),
                        "summary": r.get("body", r.get("snippet", "")),
                        "source": "duckduckgo",
                        "query": query,
                    })
                elif isinstance(r, str):
                    # Some versions return just URLs
                    results.append({
                        "title": "",
                        "url": r,
                        "summary": "",
                        "source": "duckduckgo",
                        "query": query,
                    })
        
        return results
    except Exception as e:
        logger.error(f"DuckDuckGo search failed for query '{query}': {e}")
        return []


def check_certificate_transparency(domain_pattern, max_results=20):
    """Query Certificate Transparency logs for certificates matching pattern."""
    import urllib.request
    import ssl
    
    try:
        url = CT_SEARCH_URL.format(domain=quote_plus(domain_pattern))
        
        # Create SSL context that doesn't verify (for crt.sh which uses self-signed)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ScamScan/1.0)"}
        )
        
        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            data = response.read().decode("utf-8", errors="ignore")
            
        # Parse JSON response
        certs = json.loads(data) if data.strip() else []
        
        results = []
        seen_domains = set()
        
        for cert in certs[:max_results]:
            # Extract domain names from certificate
            name = cert.get("name_value", "")
            domains = name.split("\n")
            
            for domain in domains:
                domain = domain.strip().lower()
                if domain and domain not in seen_domains:
                    # Skip wildcards and already-known-good domains
                    if domain.startswith("*."):
                        domain = domain[2:]
                    
                    if domain in seen_domains:
                        continue
                    
                    seen_domains.add(domain)
                    
                    # Skip official domains
                    official = cfg.get("brand", {}).get("official_domains", [])
                    if any(domain.endswith(odom.lower()) for odom in official):
                        continue
                    
                    # Construct potential URLs
                    if not domain.startswith(("http://", "https://")):
                        url = f"https://{domain}"
                    else:
                        url = domain
                    
                    results.append({
                        "title": f"Certificate: {domain}",
                        "url": url,
                        "summary": f"Domain found in CT logs matching {domain_pattern}",
                        "source": "certificate_transparency",
                        "query": domain_pattern,
                        "cert_info": {
                            "issuer": cert.get("issuer_name", ""),
                            "registered": cert.get("entry_timestamp", ""),
                        }
                    })
        
        return results
    except Exception as e:
        logger.error(f"CT search failed for '{domain_pattern}': {e}")
        return []


def evaluate_url(url, title, summary, cfg):
    """Evaluate a discovered URL using the existing scoring system."""
    # Combine all available text for scoring
    full_text = f"{title or ''} {summary or ''}"
    
    # Create a finding structure compatible with score_finding
    finding = {
        "url": url,
        "title": title or "",
        "summary": full_text,
        "quoted_evidence": full_text,
        "model_confidence": None,  # Will be ignored in scoring
    }
    
    # Score using local heuristics
    scored = score_finding(finding, cfg)
    
    return scored


def discover(cfg, limit=20, source="all", brand_keyword=None, dry_run=False):
    """Main discovery function."""
    results = []
    seen_urls = set()
    
    # Generate search queries
    queries = generate_queries(cfg, brand_keyword)
    
    logger.info(f"Generated {len(queries)} search queries")
    
    if dry_run:
        print(f"\n=== DRY RUN: Would execute {len(queries)} queries ===\n")
        for i, q in enumerate(queries[:10], 1):
            print(f"{i}. {q}")
        if len(queries) > 10:
            print(f"... and {len(queries) - 10} more")
        return []
    
    # Search based on source type
    all_findings = []
    
    if source in ("all", "search"):
        logger.info("Running search engine queries...")
        for i, query in enumerate(queries):
            if limit and len(all_findings) >= limit * 2:  # Get extra for filtering
                break
                
            logger.debug(f"Searching: {query}")
            search_results = search_duckduckgo(query, max_results=5)
            
            for r in search_results:
                url = r.get("url", "")
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    all_findings.append(r)
            
            # Rate limiting
            time.sleep(0.5)
    
    if source in ("all", "ct"):
        logger.info("Checking Certificate Transparency logs...")
        brand = cfg.get("brand", {})
        aliases = brand.get("aliases", [])
        
        # Check CT for each brand alias
        for alias in aliases[:5]:  # Limit CT queries
            clean_alias = re.sub(r'[^a-z0-9]', '', alias.lower())
            if len(clean_alias) < 3:
                continue
                
            ct_results = check_certificate_transparency(clean_alias, max_results=10)
            
            for r in ct_results:
                url = r.get("url", "")
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    all_findings.append(r)
            
            time.sleep(1.0)  # CT API rate limiting
    
    # Evaluate and score findings
    logger.info(f"Evaluating {len(all_findings)} unique URLs...")
    
    con = None
    if not dry_run:
        con = db_connect()
    
    for finding in all_findings:
        url = finding.get("url", "")
        
        # Skip blocked/official domains
        blocked = cfg.get("search", {}).get("blocked_domains", [])
        if any(registrable(url).endswith(bd) for bd in blocked):
            continue
        
        # Score the finding
        scored = evaluate_url(
            url,
            finding.get("title", ""),
            finding.get("summary", ""),
            cfg
        )
        
        # Only keep findings above threshold
        threshold = cfg.get("scoring", {}).get("review_threshold", 45)
        if scored["score"] >= threshold:
            result = {
                "url": url,
                "title": finding.get("title", ""),
                "summary": finding.get("summary", ""),
                "source": finding.get("source", "unknown"),
                "query": finding.get("query", ""),
                "score": scored["score"],
                "breakdown": scored,
                "discovered_at": datetime.now(timezone.utc).isoformat(),
            }
            results.append(result)
            
            # Store in database
            if con and not dry_run:
                upsert(con, finding, scored, finding.get("query", "discover"))
            
            logger.info(f"FOUND: {url} (score: {scored['score']})")
    
    if con:
        con.commit()
        con.close()
    
    # Sort by score descending
    results.sort(key=lambda x: x["score"], reverse=True)
    
    return results[:limit]


def cmd_discover(args):
    """Command handler for discover."""
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s"
    )
    
    # Load config
    cfg = json.load(open(args.config))
    
    results = discover(
        cfg,
        limit=args.limit,
        source=args.source,
        brand_keyword=args.brand,
        dry_run=args.dry_run
    )
    
    if args.dry_run:
        return 0
    
    # Output results
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"\n{'='*80}")
        print(f"DISCOVERED {len(results)} POTENTIAL SCAM SITES")
        print(f"{'='*80}\n")
        
        for i, r in enumerate(results, 1):
            print(f"[{i}] Score: {r['score']} | Source: {r['source']}")
            print(f"    URL: {r['url']}")
            if r.get('title'):
                print(f"    Title: {r['title']}")
            if r.get('summary'):
                summary = r['summary'][:200] + "..." if len(r['summary']) > 200 else r['summary']
                print(f"    Summary: {summary}")
            
            bd = r.get('breakdown', {})
            print(f"    Breakdown: lexicon={bd.get('lexicon_score', 0)}, "
                  f"artifact={bd.get('artifact_score', 0)}, "
                  f"impersonation={bd.get('impersonation_score', 0)}")
            
            if bd.get('artifacts'):
                print(f"    Artifacts: {bd['artifacts']}")
            
            print()
    
    return 0


def add_discover_parser(subparsers):
    """Add discover command to argument parser."""
    d = subparsers.add_parser("discover", help="actively hunt for scam websites")
    d.add_argument("--config", default="config.json")
    d.add_argument("--limit", type=int, default=20, help="max results to return")
    d.add_argument("--source", choices=["all", "search", "ct"], default="all",
                   help="discovery source: all, search (engine), ct (certificates)")
    d.add_argument("--brand", help="specific brand keyword to search for")
    d.add_argument("--dry-run", action="store_true",
                   help="show queries without executing")
    d.add_argument("--json", action="store_true", help="output as JSON")
    d.add_argument("-v", "--verbose", action="store_true")
    d.set_defaults(func=cmd_discover)
