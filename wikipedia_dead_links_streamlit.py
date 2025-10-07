#!/usr/bin/env python3

import streamlit as st
import requests
from bs4 import BeautifulSoup
import json
import time
import concurrent.futures
import os
from datetime import datetime
import pandas as pd
from urllib.parse import urlparse, urljoin, unquote
import whois
import socket
import re

class WikipediaDeadLinkFinder:
    def __init__(self, log_file="wikipedia_dead_links.json", available_domains_file="available_domains.json", max_workers=10):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'DeadLinkFinder/1.0 (Research project for identifying broken links)'
        })
        self.log_file = log_file
        self.available_domains_file = available_domains_file
        self.max_workers = max_workers
        self.results = self._load_existing_results()
        self.available_domains = self._load_available_domains()
        self.base_url = "https://en.wikipedia.org"
        
        # Define restricted TLDs that cannot be freely registered
        self.restricted_tlds = [
            'edu', 'gov', 'mil', 'int', 'arpa', 
            'us.gov', 'us.edu', 'ac.uk', 'gov.uk', 'mil.uk', 'ac.id', 'nhs.uk', 
            'police.uk', 'mod.uk', 'parliament.uk', 'gov.au', 'edu.au'
        ]
        
        # Define excluded domain endings that should not be included in available domains
        self.excluded_domain_endings = [
            '.de', '.bg', '.br', '.com.au', '.edu.tw', '.dk', '.com:80', '.co.in', 
            '.im', '.org:80', '.is', '.ch', '.ac.at', '.gov.ua', '.edu:8000', 
            '.gov.pt', '.pk', '.hu', '.uam.es', '.at', '.jp', '.fi'
        ]
        
    def _load_existing_results(self):
        """Load existing results from log file if it exists"""
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                st.error(f"Error loading existing log file {self.log_file}, creating new one")
                return {}
        return {}
        
    def _load_available_domains(self):
        """Load existing available domains if the file exists"""
        if os.path.exists(self.available_domains_file):
            try:
                with open(self.available_domains_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                st.error(f"Error loading available domains file {self.available_domains_file}, creating new one")
                return {}
        return {}
    
    def _save_results(self):
        """Save results to log file"""
        with open(self.log_file, 'w') as f:
            json.dump(self.results, f, indent=2)
            
    def _save_available_domains(self):
        """Save available domains to a separate file"""
        with open(self.available_domains_file, 'w') as f:
            json.dump(self.available_domains, f, indent=2)
    
    def extract_domain(self, url):
        """Extract domain name from URL"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            # Remove www. prefix if present
            if domain.startswith('www.'):
                domain = domain[4:]
            return domain
        except:
            return None
    
    def is_excluded_domain(self, domain):
        """Check if domain has an excluded ending and should not be added to available domains"""
        if not domain:
            return True
            
        # Check if domain ends with any of the excluded endings
        for ending in self.excluded_domain_endings:
            if domain.lower().endswith(ending.lower()):
                return True
                
        return False
    
    def is_restricted_tld(self, domain):
        """Check if domain has a restricted TLD that can't be freely registered"""
        if not domain:
            return False
            
        domain_parts = domain.lower().split('.')
        if len(domain_parts) < 2:
            return False
            
        # Check for TLDs like .edu and .gov
        if domain_parts[-1] in ['edu', 'gov', 'mil', 'int', 'arpa']:
            return True
            
        # Check for second-level restrictions like .ac.uk, .gov.uk, etc.
        if len(domain_parts) > 2:
            last_two = '.'.join(domain_parts[-2:])
            if last_two in self.restricted_tlds:
                return True
                
        return False
    
    def check_domain_availability(self, domain):
        """Check if a domain is potentially available for registration"""
        if not domain:
            return {
                "available": False,
                "status": "Invalid domain",
                "details": {}
            }
        
        # Check if it's an excluded domain
        if self.is_excluded_domain(domain):
            return {
                "available": False,
                "status": "Excluded domain",
                "details": {"info": "This domain has been excluded from availability checks."}
            }
        
        # Check for restricted TLDs that cannot be freely registered
        if self.is_restricted_tld(domain):
            return {
                "available": False,
                "status": "Restricted TLD (not available for general registration)",
                "details": {"info": "This is a restricted domain that requires special eligibility requirements."}
            }
            
        try:
            # Try to get WHOIS info
            w = whois.whois(domain)
            
            # If no expiration date or registrar is found, domain might be available
            if w.registrar is None:
                return {
                    "available": True,
                    "status": "Potentially available",
                    "details": {"whois": str(w)}
                }
                
            # If domain has an expiration date in the past
            if hasattr(w, 'expiration_date') and w.expiration_date:
                expiry = w.expiration_date
                if isinstance(expiry, list):
                    expiry = expiry[0]  # Take first date if it's a list
                
                if expiry < datetime.now():
                    return {
                        "available": True,
                        "status": "Expired",
                        "details": {
                            "expiration_date": str(expiry),
                            "registrar": w.registrar
                        }
                    }
            
            return {
                "available": False,
                "status": "Registered",
                "details": {
                    "registrar": w.registrar,
                    "creation_date": str(w.creation_date) if hasattr(w, 'creation_date') else "Unknown",
                    "expiration_date": str(w.expiration_date) if hasattr(w, 'expiration_date') else "Unknown"
                }
            }
            
        except whois.parser.PywhoisError:
            # If WHOIS lookup fails, try DNS lookup
            try:
                socket.gethostbyname(domain)
                return {
                    "available": False,
                    "status": "DNS record exists",
                    "details": {}
                }
            except socket.gaierror:
                # If DNS lookup fails too, domain might be available (if not restricted or excluded)
                if self.is_restricted_tld(domain) or self.is_excluded_domain(domain):
                    return {
                        "available": False,
                        "status": "Restricted TLD or excluded domain",
                        "details": {"info": "This domain is either restricted or has been excluded."}
                    }
                else:
                    return {
                        "available": True,
                        "status": "No DNS record found",
                        "details": {}
                    }
        except Exception as e:
            return {
                "available": False,
                "status": f"Error: {str(e)}",
                "details": {}
            }
            
    def search_wikipedia_text(self, query, limit=50):
        """Search Wikipedia for pages containing specific text"""
        search_url = f"{self.base_url}/w/api.php"
        params = {
            "action": "query",
            "format": "json",
            "list": "search",
            "srsearch": query,
            "srnamespace": "0",  # Main namespace (articles)
            "srlimit": str(limit)
        }
        
        try:
            response = self.session.get(search_url, params=params)
            data = response.json()
            pages = []
            
            for result in data.get("query", {}).get("search", []):
                page_title = result.get("title", "")
                page_id = result.get("pageid", 0)
                page_url = f"{self.base_url}/wiki/{page_title.replace(' ', '_')}"
                
                # Get snippet and clean HTML tags safely
                snippet = result.get("snippet", "")
                if snippet:
                    # Remove HTML tags with regex instead of BeautifulSoup
                    snippet = re.sub(r'<[^>]+>', '', snippet)
                
                pages.append({
                    "title": page_title,
                    "url": page_url,
                    "snippet": snippet,
                    "page_id": page_id
                })
                
            return pages
        except Exception as e:
            st.error(f"Error searching Wikipedia: {str(e)}")
            return []
    
    def search_categories(self, query):
        """Search for Wikipedia categories"""
        search_url = f"{self.base_url}/w/api.php"
        params = {
            "action": "query",
            "format": "json",
            "list": "search",
            "srsearch": f"Category:{query}",
            "srnamespace": "14",  # Category namespace
            "srlimit": "20"
        }
        
        try:
            response = self.session.get(search_url, params=params)
            data = response.json()
            categories = []
            
            for result in data.get("query", {}).get("search", []):
                category_title = result.get("title", "")
                category_url = f"{self.base_url}/wiki/{category_title.replace(' ', '_')}"
                categories.append({
                    "title": category_title,
                    "url": category_url
                })
                
            return categories
        except Exception as e:
            st.error(f"Error searching categories: {str(e)}")
            return []
    
    def get_pages_in_category(self, category_url):
        """Get pages in a Wikipedia category"""
        try:
            response = self.session.get(category_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find the main content area
            content_div = soup.find('div', {'id': 'mw-content-text'})
            if not content_div:
                return []
            
            # Find all article links in the category
            pages = []
            for item in content_div.find_all('li'):
                link = item.find('a')
                if not link or not link.has_attr('href') or not link.has_attr('title'):
                    continue
                
                # Skip subcategories and files
                href = link['href']
                if 'Category:' in href or 'File:' in href:
                    continue
                
                if href.startswith('/wiki/'):
                    page_url = urljoin(self.base_url, href)
                    pages.append({
                        'title': link['title'],
                        'url': page_url
                    })
            
            return pages
        except Exception as e:
            st.error(f"Error getting pages in category: {str(e)}")
            return []
            
    def extract_external_links(self, soup):
        """Extract external links from a Wikipedia article"""
        external_links = []
        
        # Find external links sections
        ext_links_section = soup.find('span', {'id': 'External_links'})
        if ext_links_section:
            # Find the UL list after the external links heading
            parent_heading = ext_links_section.parent
            next_ul = parent_heading.find_next('ul')
            if next_ul:
                for li in next_ul.find_all('li'):
                    links = li.find_all('a', {'class': 'external'})
                    for link in links:
                        if link.has_attr('href'):
                            url = link['href']
                            # Skip web.archive.org links
                            if url.startswith('https://web.archive.org'):
                                continue
                            external_links.append({
                                'url': url,
                                'text': link.get_text().strip()
                            })
        
        # Also check for citation links
        citation_links = soup.find_all('a', {'class': 'external'})
        for link in citation_links:
            if link.has_attr('href'):
                url = link['href']
                # Skip web.archive.org links
                if url.startswith('https://web.archive.org'):
                    continue
                external_links.append({
                    'url': url,
                    'text': link.get_text().strip()
                })
                
        return external_links
    
    def check_link_status(self, link):
        """Check if a link is dead"""
        url = link['url']
        try:
            response = self.session.head(url, timeout=10, allow_redirects=True)
            status_code = response.status_code
        except Exception as e:
            status_code = f"Error: {str(e)}"
            
        # If head request fails, try GET
        if isinstance(status_code, str) or status_code >= 400:
            try:
                response = self.session.get(url, timeout=10)
                status_code = response.status_code
            except Exception as e:
                status_code = f"Error: {str(e)}"
                
        result = {
            'url': url,
            'text': link['text'],
            'status_code': status_code,
            'timestamp': datetime.now().isoformat()
        }
        
        # If it's a dead link, check domain availability
        if isinstance(status_code, str) or status_code >= 400:
            domain = self.extract_domain(url)
            if domain:
                domain_info = self.check_domain_availability(domain)
                result['domain'] = domain
                result['domain_available'] = domain_info['available']
                result['domain_status'] = domain_info['status']
                result['domain_details'] = domain_info['details']
                
                # If domain is available and not excluded, add to available domains list
                if domain_info['available'] and not self.is_excluded_domain(domain):
                    domain_key = domain
                    if domain_key not in self.available_domains:
                        self.available_domains[domain_key] = {
                            'domain': domain,
                            'status': domain_info['status'],
                            'details': domain_info['details'],
                            'found_on': datetime.now().isoformat(),
                            'sources': []
                        }
                    
                    # Add this source to the domain's sources list
                    source_info = {
                        'url': url,
                        'text': link['text'],
                        'article_title': link.get('article_title', 'Unknown'),
                        'article_url': link.get('article_url', 'Unknown')
                    }
                    
                    # Check if this source is already in the list
                    source_exists = False
                    for source in self.available_domains[domain_key]['sources']:
                        if source.get('url') == url and source.get('article_url') == link.get('article_url', 'Unknown'):
                            source_exists = True
                            break
                            
                    if not source_exists:
                        self.available_domains[domain_key]['sources'].append(source_info)
                        self._save_available_domains()
        
        return result
    
    def process_article(self, article_url, article_title=None):
        """Process a Wikipedia article and find dead links"""
        try:
            response = self.session.get(article_url, timeout=10)
            
            if response.status_code != 200:
                st.error(f"Failed to retrieve article: {article_url}")
                return []
                
            soup = BeautifulSoup(response.text, 'html.parser')
            if not article_title:
                title_elem = soup.find('h1', {'id': 'firstHeading'})
                article_title = title_elem.get_text() if title_elem else "Unknown Title"
            
            external_links = self.extract_external_links(soup)
            
            dead_links = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Add article info to each link
                for link in external_links:
                    link['article_title'] = article_title
                    link['article_url'] = article_url
                
                futures = [executor.submit(self.check_link_status, link) for link in external_links]
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    status = result['status_code']
                    
                    # Consider status codes >= 400 or errors as dead links
                    if isinstance(status, str) or status >= 400:
                        result['article_title'] = article_title
                        result['article_url'] = article_url
                        dead_links.append(result)
                        
                        # Update results in real-time
                        link_id = f"{result['url']}_{result['article_url']}"
                        self.results[link_id] = result
                        self._save_results()
            
            return dead_links
            
        except Exception as e:
            st.error(f"Error processing article: {str(e)}")
            return []
            
    def batch_process_articles(self, pages, max_pages=None, progress_bar=None):
        """Process a batch of articles to find dead links and available domains"""
        if max_pages:
            pages = pages[:max_pages]
            
        all_dead_links = []
        processed_count = 0
        
        for i, page in enumerate(pages):
            st.write(f"Processing article: {page['title']} ({i+1}/{len(pages)})")
            
            dead_links = self.process_article(page['url'], page['title'])
            all_dead_links.extend(dead_links)
            processed_count += 1
            
            if progress_bar:
                progress_bar.progress((i + 1) / len(pages))
            
            # Sleep to avoid overwhelming the server
            time.sleep(1)
            
        return all_dead_links, processed_count
    
    def crawl_category(self, category_url, max_pages=10, progress_bar=None):
        """Crawl pages in a Wikipedia category"""
        pages = self.get_pages_in_category(category_url)
        return self.batch_process_articles(pages, max_pages, progress_bar)

# Streamlit UI
st.set_page_config(page_title="Wikipedia Dead Link Finder", page_icon="🔍", layout="wide")

st.title("🔍 Wikipedia Dead Link Finder by metehan.ai")
st.write("Find dead links in Wikipedia articles and discover available domains for registration")

# Initialize the finder
if 'finder' not in st.session_state:
    st.session_state.finder = WikipediaDeadLinkFinder()

# Sidebar configuration
st.sidebar.header("Configuration")
log_file = st.sidebar.text_input("Log file path", value="wikipedia_dead_links.json")
available_domains_file = st.sidebar.text_input("Available domains file", value="available_domains.json")
max_workers = st.sidebar.slider("Max concurrent requests", min_value=1, max_value=20, value=10)
max_pages = st.sidebar.slider("Max pages to process", min_value=1, max_value=20, value=10)

# Update finder if config changes
if (log_file != st.session_state.finder.log_file or 
    available_domains_file != st.session_state.finder.available_domains_file or
    max_workers != st.session_state.finder.max_workers):
    st.session_state.finder = WikipediaDeadLinkFinder(
        log_file=log_file,
        available_domains_file=available_domains_file,
        max_workers=max_workers
    )

# Display excluded domains in sidebar
with st.sidebar.expander("Excluded Domain Endings"):
    st.write("The following domain endings will not be included in available domains:")
    for ending in st.session_state.finder.excluded_domain_endings:
        st.write(f"- `{ending}`")

# Search method tabs
search_tab, category_tab, domains_tab = st.tabs(["Search by Text", "Search by Category", "Available Domains"])

# Helper function to display dead links results
def display_dead_links_results(dead_links):
    st.header("Dead Links Found")
    
    # Filter options
    show_available_only = st.checkbox("Show only potentially available domains", key="show_available")
    
    # Convert to DataFrame for display
    results_data = []
    for link in dead_links:
        domain_available = link.get('domain_available', False)
        
        # Skip if we're only showing available domains and this one isn't available
        if show_available_only and not domain_available:
            continue
            
        results_data.append({
            "Article": link['article_title'],
            "Link Text": link['text'],
            "URL": link['url'],
            "Status": link['status_code'],
            "Domain": link.get('domain', 'Unknown'),
            "Available": "✅" if domain_available else "❌",
            "Domain Status": link.get('domain_status', 'Unknown')
        })
        
    results_df = pd.DataFrame(results_data)
    
    if not results_data:
        st.info("No available domains found" if show_available_only else "No dead links found")
    else:
        st.dataframe(results_df)
        
        # Domain details expander
        with st.expander("Domain Details"):
            for link in dead_links:
                if 'domain' in link and ('domain_details' in link or 'domain_status' in link):
                    domain = link['domain']
                    status = link.get('domain_status', 'Unknown')
                    available = link.get('domain_available', False)
                    
                    if show_available_only and not available:
                        continue
                        
                    st.markdown(f"### {domain}")
                    st.write(f"Status: {status}")
                    st.write(f"Available: {'Yes' if available else 'No'}")
                    
                    details = link.get('domain_details', {})
                    if details:
                        st.json(details)
        
        # Download button
        csv = results_df.to_csv(index=False)
        st.download_button(
            "Download results as CSV",
            csv,
            "wikipedia_dead_links.csv",
            "text/csv",
            key='download-csv'
        )

# Text search tab
with search_tab:
    st.header("Search Wikipedia by Text")
    text_query = st.text_input("Enter search terms", key="text_search")
    search_limit = st.slider("Number of results", min_value=10, max_value=20, value=10, step=10)
    
    if st.button("Search Pages", key="search_text_btn"):
        if text_query:
            with st.spinner("Searching Wikipedia..."):
                search_results = st.session_state.finder.search_wikipedia_text(text_query, limit=search_limit)
                
            if search_results:
                st.session_state.search_results = search_results
                st.success(f"Found {len(search_results)} pages")
                
                # Display search results
                search_df = pd.DataFrame([
                    {"Title": p["title"], "Snippet": p["snippet"]} 
                    for p in search_results
                ])
                st.dataframe(search_df)
            else:
                st.warning("No pages found matching your search")
        else:
            st.warning("Please enter search terms")
    
    # Only show the process button if there are search results
    if 'search_results' in st.session_state and st.session_state.search_results:
        if st.button("Process All Found Pages", key="process_pages_btn"):
            progress_bar = st.progress(0)
            
            with st.spinner(f"Processing {len(st.session_state.search_results)} pages..."):
                dead_links, processed_pages = st.session_state.finder.batch_process_articles(
                    st.session_state.search_results,
                    max_pages=max_pages,
                    progress_bar=progress_bar
                )
                
            st.success(f"Process complete! Processed {processed_pages} pages and found {len(dead_links)} dead links")
            
            # Show available domains summary
            available_count = len(st.session_state.finder.available_domains)
            if available_count > 0:
                st.success(f"Found {available_count} potentially available domains!")
                st.info(f"View them in the 'Available Domains' tab")
            
            # Show results
            if dead_links:
                display_dead_links_results(dead_links)
            else:
                st.info("No dead links found in these pages")

# Category search tab
with category_tab:
    st.header("Search Wikipedia by Category")
    category_query = st.text_input("Enter a category name", key="category_search")
    
    if st.button("Search Categories", key="search_category_btn"):
        if category_query:
            with st.spinner("Searching categories..."):
                categories = st.session_state.finder.search_categories(category_query)
                
            if categories:
                st.session_state.categories = categories
                st.success(f"Found {len(categories)} categories")
                
                # Convert to DataFrame for nicer display
                category_df = pd.DataFrame(categories)
                category_df.index = range(1, len(category_df) + 1)  # 1-based index
                
                st.dataframe(category_df)
                
                selected_idx = st.number_input("Select category number", min_value=1, max_value=len(categories), step=1)
                
                if st.button("Crawl Selected Category"):
                    selected_category = categories[selected_idx - 1]
                    st.write(f"Crawling category: **{selected_category['title']}**")
                    st.write(f"URL: {selected_category['url']}")
                    
                    progress_bar = st.progress(0)
                    
                    with st.spinner(f"Crawling {selected_category['title']}..."):
                        dead_links, processed_pages = st.session_state.finder.crawl_category(
                            selected_category['url'], 
                            max_pages=max_pages,
                            progress_bar=progress_bar
                        )
                        
                    st.success(f"Crawl complete! Processed {processed_pages} pages and found {len(dead_links)} dead links")
                    
                    # Show available domains summary
                    available_count = len(st.session_state.finder.available_domains)
                    if available_count > 0:
                        st.success(f"Found {available_count} potentially available domains!")
                        st.info(f"View them in the 'Available Domains' tab")
                    
                    # Show results
                    if dead_links:
                        display_dead_links_results(dead_links)
                    else:
                        st.info("No dead links found in this category")
            else:
                st.warning("No categories found")
        else:
            st.warning("Please enter a category name")

# Available domains tab
with domains_tab:
    st.header("Available Domains")
    
    available_domains = st.session_state.finder.available_domains
    available_count = len(available_domains)
    
    st.write(f"Found {available_count} potentially available domains")
    
    if available_count > 0:
        # Filter options
        domain_filters = st.multiselect(
            "Filter by domain status",
            options=["Potentially available", "Expired", "No DNS record found"],
            default=["Potentially available", "Expired", "No DNS record found"]
        )
        
        # Convert to DataFrame for display
        domains_data = []
        for domain, info in available_domains.items():
            # Skip if not matching filter
            if info.get('status') not in domain_filters:
                continue
                
            sources_count = len(info.get('sources', []))
            domains_data.append({
                "Domain": domain,
                "Status": info.get('status', 'Unknown'),
                "Found On": info.get('found_on', 'Unknown'),
                "Sources Count": sources_count
            })
            
        if domains_data:
            domains_df = pd.DataFrame(domains_data)
            st.dataframe(domains_df)
            
            # Domain details expander
            with st.expander("Domain Details"):
                for domain, info in available_domains.items():
                    if info.get('status') not in domain_filters:
                        continue
                        
                    st.markdown(f"### {domain}")
                    st.write(f"Status: {info.get('status', 'Unknown')}")
                    st.write(f"Found on: {info.get('found_on', 'Unknown')}")
                    
                    sources = info.get('sources', [])
                    st.write(f"Found in {len(sources)} links:")
                    
                    for i, source in enumerate(sources):
                        st.write(f"{i+1}. **{source.get('article_title', 'Unknown')}**")
                        st.write(f"   Link: [{source.get('text', 'Link')}]({source.get('url', '#')})")
                        st.write(f"   Article: [{source.get('article_title', 'Article')}]({source.get('article_url', '#')})")
                    
                    details = info.get('details', {})
                    if details:
                        st.json(details)
            
            # Download button
            csv = domains_df.to_csv(index=False)
            st.download_button(
                "Download available domains as CSV",
                csv,
                "available_domains.csv",
                "text/csv",
                key='download-domains-csv'
            )
        else:
            st.info("No domains matching the selected filters")
    else:
        st.info("No available domains found yet. Run a search to find some!") 