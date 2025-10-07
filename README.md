---
title: Link Lazarus Method
emoji: 🔗
colorFrom: blue
colorTo: red
sdk: streamlit
sdk_version: "1.32.2"
app_file: wikipedia_dead_links_streamlit.py
pinned: false
---



# The Link Lazarus Method: Wikipedia Dead Link Finder by metehan.ai - Streamlit Version

A Streamlit web application for finding and logging dead (broken) external links in Wikipedia articles, identifying potentially available domains for registration, and saving them to a dedicated database.

## Features

- **Multiple Search Methods**:
  - Search by text to find Wikipedia articles
  - Search by category to find related articles
- **Dead Link Detection**: Checks external links for HTTP errors or connection issues
- **Domain Availability**: Identifies which domains from dead links might be available for registration
- **Restricted TLD Filtering**: Automatically identifies and excludes restricted domains (.edu, .gov, etc.)
- **Available Domains Database**: Maintains a separate database of potentially available domains
- **Real-time Logging**: Saves dead links and available domains to JSON files as they're found
- **Result Visualization**: Displays results in an interactive table with filtering options
- **Export to CSV**: Download results as a CSV file
- **Web Archive Filter**: Automatically ignores links from web.archive.org
- **Configurable**: Adjust settings via the sidebar

## Requirements

- Python 3.6+
- Required packages listed in `requirements_streamlit.txt`

## Installation

```
pip install -r requirements_streamlit.txt
```

## Usage

Run the Streamlit app:

```
streamlit run wikipedia_dead_links_streamlit.py
```

The application will open in your default web browser with three main tabs:

### 1. Search by Text

- Enter search terms to find Wikipedia articles containing that text
- View search results with snippets
- Process all found pages to check for dead links and available domains

### 2. Search by Category

- Enter a category name to find Wikipedia categories
- Select a category to crawl its pages
- Find dead links and available domains within those pages

### 3. Available Domains

- View all potentially available domains found during searches
- Filter domains by status (potentially available, expired, etc.)
- See details about each domain including where it was found
- Download the list as a CSV file

## How Domain Availability Works

The app uses these methods to determine if a domain might be available:

1. **WHOIS Lookup**: Checks if the domain has registration information
2. **Expiration Check**: Identifies domains with expired registration dates
3. **DNS Lookup**: Verifies if the domain has active DNS records
4. **TLD Restriction Check**: Identifies restricted TLDs that cannot be freely registered

Domains are flagged as potentially available if:
- No WHOIS registration data is found
- The domain's expiration date has passed
- No DNS records exist for the domain
- The domain does NOT have a restricted TLD (.edu, .gov, .mil, etc.)

### Restricted TLDs (Optional)

The following TLDs are recognized as restricted and will never be reported as available, if you choose to filter them:
- .edu - Educational institutions
- .gov - Government entities
- .mil - Military organizations
- .int - International organizations
- Country-specific restrictions like .ac.uk, .gov.uk, etc.

**Note**: For definitive availability, you should verify with a domain registrar. The tool provides a starting point for identifying potential opportunities.

## Configuration Options

- **Log file path**: Where to save the dead links JSON results
- **Available domains file**: Where to save the available domains database
- **Max concurrent requests**: Number of links to check simultaneously
- **Max pages to process**: Limit the number of articles to process

## Output Files

The app generates two main JSON files:

1. **wikipedia_dead_links.json**: Contains details about all dead links found
2. **available_domains.json**: Contains only the potentially available domains and where they were found

You can also download results as CSV files directly from the app. Make sure follow on X @metehan777 and LinkedIn www.linkedin.com/in/metehanyesilyurt for the upcoming updates and more tips&tools.