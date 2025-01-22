#!/usr/bin/env python

# Standard

import os
import sys

import argparse

import difflib
import logging
import tempfile
import subprocess
import socket

# Dependent

import ads
import requests
from lxml import html

from .bibdesk import BibDesk
from .prefs import Preferences
from . import __version__

import logging
logger = logging.getLogger(__name__)

import concurrent.futures


def main():
    """
    Parse options and launch main loop
    """

    description = """

ads2bibdesk helps you add astrophysics articles listed on NASA/ADS
to your BibDesk database using the ADS Developer API

Different from J.Sick's original `ads_bibdesk` or `adsbibdesk`, ads2bibdesk require the user
to specify a personal ADS API key (per the new ADS policy). The metadata query will be performed
using the API python client maintained by Andy Casey: 
  http://ads.readthedocs.io

The API key can be set with the following options:
 - your ads2bibdesk preference file: ~/.ads/ads2bibdesk.cfg, 
 - the API client key file: ~/.ads/dev_key
 - an environment variable named ADS_DEV_KEY (following the ads python package's instruction)

"""

    parser = argparse.ArgumentParser(description=description,
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-d', '--debug',
                        dest="debug", action="store_true",
                        help="Debug mode; prints extra statements")

    parser.add_argument('article_identifier', type=str,
                        help="""The identifier of an article could be:
  - ADS bibcode (e.g. 1998ApJ...500..525S, 2019arXiv190404507R)
  - arXiv identifier (e.g. 0911.4956).
  - article doi (e.g. 10.3847/1538-4357/aafd37)""")

    args = parser.parse_args()

    prefs_class = Preferences()
    prefs = prefs_class.prefs
    log_path = prefs_class.log_path
    prefs_path = prefs_class.prefs_path

    if args.debug == True:
        prefs['options']['debug'] = 'True'

    """
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s %(name)s %(levelname)s %(message)s',
        filename=log_path)  
    if  'true' not in prefs['options']['debug'].lower(): 
        logging.getLogger('').setLevel(logger.info)
    """

    fh = logging.FileHandler(log_path, mode='a')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(CustomFormatter())

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(CustomFormatter())

    # toplogger=logging.getLogger('')
    toplogger = logging.getLogger('ads2bibdesk')
    toplogger.setLevel(logging.DEBUG)
    toplogger.handlers = []
    toplogger.addHandler(fh)
    toplogger.addHandler(ch)

    if 'true' not in prefs['options']['debug'].lower():
        ch.setLevel(logging.INFO)
        fh.setLevel(logging.INFO)
        ch.setFormatter('')
    else:
        ch.setLevel(logging.DEBUG)
        fh.setLevel(logging.DEBUG)

    logger.info("Starting ADS to BibDesk")
    logger.debug("ADS to BibDesk version {}".format(__version__))
    logger.debug("Python: {}".format(sys.version))

    article_status = process_article(args, prefs)


class CustomFormatter(logging.Formatter):
    """
    customized logging formatter which can handle mutiple-line msgs
    """

    def format(self, record: logging.LogRecord):
        save_msg = record.msg
        output = []
        datefmt = '%Y-%m-%d %H:%M:%S'
        s = "{} {:<32} {:<8} : ".format(self.formatTime(record, datefmt),
                                        record.name+'.'+record.funcName,
                                        "[" + record.levelname + "]")
        for line in save_msg.splitlines():
            record.msg = line
            output.append(s+line)

        output = '\n'.join(output)
        record.msg = save_msg
        record.message = output

        return output


def process_article(args, prefs):
    """
    """

    bibdesk = BibDesk()

    article_status = process_token(args.article_identifier, prefs, bibdesk)

    bibdesk.app.dealloc()

    return article_status


def process_token(article_identifier, prefs, bibdesk):
    """
    Process a single article token from the user, adding it to BibDesk.
    """
    if 'true' in prefs['options']['alert_sound'].lower():
        alert_sound = 'Frog'
    else:
        alert_sound = None

    if 'dev_key' not in prefs['default']['ads_token']:
        ads.config.token = prefs['default']['ads_token']

    # Make API calls in parallel if possible
    try:
        ads_query = ads.SearchQuery(identifier=article_identifier,
                                fl=['author', 'first_author',
                                    'bibcode', 'identifier', 'alternate_bibcode', 'id',
                                    'year', 'title', 'abstract', 'links_data', 'esources', 'bibstem'])
        ads_articles = list(ads_query)
        
        if len(ads_articles) == 1:
            # Start BibTeX export query early
            ads_article = ads_articles[0]
            if 'true' in prefs['options']['download_pdf'].lower():
                # Start PDF process in parallel with BibTeX query
                pdf_future = concurrent.futures.ThreadPoolExecutor().submit(
                    process_pdf, ads_article.bibcode, ads_article.esources, prefs)
            
            use_bibtexabs = False
            ads_bibtex = ads.ExportQuery(
                bibcodes=ads_article.bibcode, 
                format='bibtexabs' if use_bibtexabs else 'bibtex').execute()
        else:
            logger.debug(
                ' Zero or Multiple ADS entries for the article identifiier: {}'.format(article_identifier))
            notify('Found Zero or Multiple ADS antries for ',
                   article_identifier, ' No update in BibDesk', alert_sound=alert_sound)
            return False
            
    except Exception as e:
        logger.info("API response error: {}".format(str(e)))
        notify('API response error', 'key:'+prefs['default']['ads_token'],
               'Error accessing ADS API', alert_sound=alert_sound)
        return False

    # Handle duplicates more efficiently
    found = difflib.get_close_matches(
        ads_article.title[0], bibdesk.titles, n=1, cutoff=.7)

    if found:
        pid = bibdesk.pid(found[0])
        if difflib.SequenceMatcher(
                None,
                bibdesk.authors(pid)[0],
                ads_article.author[0]).ratio() > .6:
            # Get duplicate data separately to avoid tuple access issues
            abstract = bibdesk('return abstract', pid).stringValue()
            fields = bibdesk('return name of fields', pid, True)
            values = bibdesk('return value of fields', pid, True)
            note = bibdesk('return its note', pid).stringValue()
            cite_key = bibdesk('return cite key', pid).stringValue()
            
            if not abstract or difflib.SequenceMatcher(
                    None, abstract, ads_article.abstract).ratio() > .6:
                kept_groups = bibdesk.get_groups(pid)
                kept_fields = dict((k, v) for k, v in zip(fields, values) if k != 'Adscomment')
                kept_fields['BibDeskAnnotation'] = note
                
                notify('Duplicate publication removed',
                       cite_key, ads_article.title[0], alert_sound=alert_sound)
                logger.info('Duplicate publication removed: {}'.format(cite_key))
                
                kept_pdfs = bibdesk.safe_delete(pid)
                bibdesk.refresh()

    # Add new entry and set fields in batches
    ads_bibtex_clean = ads_bibtex.replace('\\', r'\\').replace('"', r'\"')
    pub = bibdesk(f'import from "{ads_bibtex_clean}"')
    pub = pub.descriptorAtIndex_(1).descriptorAtIndex_(3).stringValue()
    bibdesk('set cite key to generated cite key', pub)
    
    # Set abstract if available
    if ads_article.abstract is not None:
        ads_abstract_clean = ads_article.abstract.replace('\\', r'\\').replace(
            '"', r'\"').replace('}', ' ').replace('{', ' ')
        bibdesk(f'set abstract to "{ads_abstract_clean}"', pub)
    
    # Handle PDF and URLs in parallel if possible
    if 'true' in prefs['options']['download_pdf'].lower():
        pdf_filename, pdf_status = pdf_future.result()
    else:
        pdf_filename = '.null'
        pdf_status = False

    # Handle PDF and URLs
    if pdf_filename.endswith('.pdf') and pdf_status:
        bibdesk(f'add POSIX file "{pdf_filename}" to beginning of linked files', pub)
        bibdesk('auto file', pub)
        notify('New publication added with PDF',
               bibdesk('cite key', pub).stringValue(),
               ads_article.title[0], alert_sound=alert_sound)
    else:
        if not pdf_status and pdf_filename.startswith('http'):
            bibdesk(f'make new linked URL at end of linked URLs with data "{pdf_filename}"', pub)
        elif doi := bibdesk('value of field "doi"', pub).stringValue():
            doi_url = f"https://doi.org/{doi}"
            bibdesk(f'make new linked URL at end of linked URLs with data "{doi_url}"', pub)

    # Add additional URLs
    if 'EPRINT_HTML' in ads_article.esources:
        eprint_url = get_esource_link(ads_article.bibcode, esource_type='eprint_html')
        bibdesk(f'make new linked URL at end of linked URLs with data "{eprint_url}"', pub)

    # Add old annotated files if any
    if 'kept_pdfs' in locals() and kept_pdfs:
        for pdf in kept_pdfs:
            bibdesk(f'add POSIX file "{pdf}" to end of linked files', pub)

    # Add back custom fields from duplicate
    if 'kept_fields' in locals():
        bibdesk_annotation = kept_fields.pop("BibDeskAnnotation", '')
        bibdesk(f'set its note to "{bibdesk_annotation}"', pub)
        newFields = bibdesk('return name of fields', pub, True)
        for k, v in list(kept_fields.items()):
            if k not in newFields:
                bibdesk(f'set value of field "{k}" to "{v}"', pub)

    # Add back static groups
    if 'kept_groups' in locals() and kept_groups:
        new_groups = bibdesk.add_groups(pub, kept_groups)

    # Log and save
    logger.info('New publication added: {} - {}'.format(
        bibdesk('cite key', pub).stringValue(),
        ads_article.title[0]))
    
    bibdesk('save')
    logger.debug("BibDesk file saved")

    return True


def process_pdf(article_bibcode, article_esources,
                prefs=None,
                esource_types=['ads_pdf', 'ads_scan', 'pub_pdf', 'pub_html']):
    """
    article_bibcode:    ADS bibcode
    article_esources:   esources available for this specific article
    esource_types:      the esource type order to try for PDF downloading
                        Default order prioritizes published versions:
                        1. ads_pdf: ADS's PDF version (preferred)
                        2. ads_scan: ADS's scanned version
                        3. pub_pdf: Publisher's PDF version
                        4. pub_html: Publisher's HTML version (to extract PDF)
                        Note: eprint_pdf will only be tried if no published version exists
    """
    pdf_status = False
    pdf_filename = '.null'
    verification_urls = []  # Store URLs that need verification
    
    # Create a requests session to maintain cookies and connection pooling
    session = requests.Session()
    # Set reasonable timeouts and headers
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/pdf,application/x-pdf,*/*',
        'Accept-Language': 'en-US,en;q=0.9',
    })
    # Enable connection pooling
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=10,
        pool_maxsize=10,
        max_retries=3,
        pool_block=False
    )
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    # Check if published versions exist
    has_published = any(source in article_esources for source in ['PUB_PDF', 'PUB_HTML', 'ADS_PDF', 'ADS_SCAN'])
    
    # If no published versions, add eprint_pdf to sources
    if not has_published and 'EPRINT_PDF' in article_esources:
        esource_types = list(esource_types) + ['eprint_pdf']

    # Try each source in order
    for esource_type in esource_types:
        if esource_type.upper() not in article_esources:
            continue
        
        esource_url = get_esource_link(article_bibcode, esource_type=esource_type)
        logger.debug(f"Trying source: {esource_type} - {esource_url}")
        
        try:
            # For ADS sources, only try direct download
            if esource_type.startswith('ads_'):
                pdf_status, pdf_filename, needs_verification = try_direct_download(session, esource_url)
                if needs_verification:
                    verification_urls.append((esource_type, esource_url))
                if pdf_status:
                    logger.debug(f"Successfully downloaded from {esource_type}")
                    break
                continue
                
            # For other sources, try the full download pipeline
            pdf_status, pdf_filename, needs_verification = try_direct_download(session, esource_url)
            if needs_verification:
                verification_urls.append((esource_type, esource_url))
            if pdf_status:
                logger.debug(f"Successfully downloaded from {esource_type}")
                break
                
            # If direct download fails and it's a publisher URL, try proxy
            if not pdf_status and 'pub' in esource_type:
                if prefs and prefs['proxy']['ssh_user'] != 'None' and prefs['proxy']['ssh_server'] != 'None':
                    pdf_status = process_pdf_proxy(esource_url, pdf_filename,
                                                   prefs['proxy']['ssh_user'],
                                                   prefs['proxy']['ssh_server'],
                                                   port=prefs['proxy']['ssh_port'])
                    if pdf_status:
                        logger.debug(f"Successfully downloaded via proxy from {esource_type}")
                        break
                        
                # If proxy fails, try alternative sources
                if not pdf_status and esource_type == 'pub_html':
                    pdf_status, pdf_filename, needs_verification = try_html_to_pdf(session, esource_url)
                    if needs_verification:
                        verification_urls.append((esource_type, esource_url))
                    if pdf_status:
                        logger.debug(f"Successfully extracted PDF from HTML for {esource_type}")
                        break
                        
        except Exception as e:
            logger.debug(f"Download failed for {esource_type}: {str(e)}")
            continue

    if not pdf_status and verification_urls:
        # If no PDF was downloaded but we found URLs requiring verification
        # Open the first verification URL in default browser
        verification_url = verification_urls[0][1]
        logger.info(f"Opening verification URL in browser: {verification_url}")
        subprocess.run(['open', verification_url])
        return verification_url, False

    return pdf_filename, pdf_status


def try_direct_download(session, url):
    """Try to download PDF directly from the URL"""
    logger.debug(f"Attempting direct download: {url}")
    
    try:
        # Add timeout to avoid hanging
        response = session.get(url, allow_redirects=True, timeout=(5, 20))  # (connect timeout, read timeout)
        
        # Check for human verification pages or redirects to login/authentication
        needs_verification = False
        if response.status_code in [403, 401]:  # Unauthorized or Forbidden
            needs_verification = True
        elif any(text in response.text.lower() for text in ['captcha', 'verification', 'robot', 'human', 'sign in', 'login', 'authenticate']):
            needs_verification = True
        elif 'oup.com' in response.url or 'academic.oup.com' in response.url:  # Special case for Oxford University Press
            needs_verification = True
            
        if needs_verification:
            logger.debug("Human verification detected")
            return False, response.url, True  # Return the final URL after redirects
            
        # Create temporary file
        fd, pdf_filename = tempfile.mkstemp(suffix='.pdf')
        if response.status_code == 200:
            # Write in chunks to handle large files better
            with os.fdopen(fd, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            
            # Verify it's actually a PDF
            if 'PDF document' in get_filetype(pdf_filename):
                logger.debug(f"Successfully downloaded PDF from {url}")
                return True, pdf_filename, False
                
        return False, pdf_filename, False
        
    except requests.Timeout:
        logger.debug(f"Download timed out for {url}")
        return False, '.null', False
    except Exception as e:
        logger.debug(f"Direct download failed: {str(e)}")
        return False, '.null', False


def try_html_to_pdf(session, url):
    """Try to extract PDF URL from HTML page and download"""
    logger.debug(f"Attempting HTML-to-PDF extraction: {url}")
    
    try:
        # Add timeout
        response = session.get(url, timeout=(5, 20))  # (connect timeout, read timeout)
        if response.status_code != 200:
            return False, '.null', False
            
        # Check for verification pages or redirects to login/authentication
        needs_verification = False
        if response.status_code in [403, 401]:  # Unauthorized or Forbidden
            needs_verification = True
        elif any(text in response.text.lower() for text in ['captcha', 'verification', 'robot', 'human', 'sign in', 'login', 'authenticate']):
            needs_verification = True
        elif 'oup.com' in response.url or 'academic.oup.com' in response.url:  # Special case for Oxford University Press
            needs_verification = True
            
        if needs_verification:
            logger.debug("Human verification detected on HTML page")
            return False, response.url, True
            
        # Try multiple methods to find PDF link
        pdf_url = None
        
        # Method 1: Check meta tags
        tree = html.fromstring(response.content)
        meta_pdf_urls = tree.xpath("//meta[@name='citation_pdf_url']/@content")
        if meta_pdf_urls:
            pdf_url = meta_pdf_urls[0]
            
        # Method 2: Look for PDF links in specific patterns
        if not pdf_url:
            if 'annualreviews.org' in url:
                pdf_url = url.replace('/doi/', '/doi/pdf/')
            elif 'link.springer.com' in url:
                pdf_url = url.replace('book', 'content/pdf').replace('article', 'content/pdf')+'.pdf'
            elif 'science.org' in url or 'sciencemag.org' in url:
                pdf_url = url + '/pdf'
            elif 'academic.oup.com' in url:
                pdf_url = url.replace('/abstract/', '/pdf/')
            else:
                # Generic attempt
                pdf_url = url + '.pdf'
        
        if pdf_url:
            status, filename, needs_verification = try_direct_download(session, pdf_url)
            return status, filename, needs_verification
            
        return False, '.null', False
        
    except requests.Timeout:
        logger.debug(f"HTML extraction timed out for {url}")
        return False, '.null', False
    except Exception as e:
        logger.debug(f"HTML-to-PDF extraction failed: {str(e)}")
        return False, '.null', False


def process_pdf_proxy(pdf_url, pdf_filename, user, server, port=22):

    client = socket.gethostname().replace(' ', '')
    tmpfile = '/tmp/adsbibdesk.{}.pdf'.format(client)
    cmd1 = 'ssh -p {} {}@{} \"touch {}; '.format(port, user, server, tmpfile)
    cmd1 += 'curl --output {} '.format(tmpfile)
    cmd1 += '-J -L --referer \\";auto\\"  '
    cmd1 += '--user-agent \\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 '
    cmd1 += '(KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36\\" \\"{}\\"\"'.format(pdf_url)

    cmd2 = 'scp -P {} -q {}@{}:{} {}'.format(port,
                                             user, server, tmpfile, pdf_filename)

    logger.debug("try >>> {}".format(pdf_url))
    logger.debug("run >>> {}".format(cmd1))
    subprocess.Popen(cmd1, shell=True,
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    logger.debug("run >>> {}".format(cmd2))
    subprocess.Popen(cmd2, shell=True,
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()

    if 'PDF document' in get_filetype(pdf_filename):
        pdf_status = True
        logger.debug("try succeeded >>> {}".format(pdf_url))
    else:
        pdf_status = False
        logger.debug("try failed >>> {}".format(pdf_url))

    return pdf_status


def get_esource_link(article_bibcode, esource_type='pub_pdf',
                     gateway_url="https://ui.adsabs.harvard.edu/link_gateway"):
    """
    ADS offers esource urls like this:
        https://ui.adsabs.harvard.edu/link_gateway/2001A%26A...366...62A/{PUB/EPRINT/ADS}_{PDF/HTML}

    Possible esource_type:
        from publishers:    PUB_PDF, PUB_HTML
        from arxiv:         EPRINT_PDF, EPRINT_HTML
        from ADS:           ADS_PDF, ADS_SCAN
        from author:        AUTHOR_PDF

    note: not necessarily all esources are available for a article (please check fl='links_data')

    """
    return gateway_url+'/'+article_bibcode+'/'+esource_type.upper()


def get_filetype(filename):
    x = subprocess.Popen('file "{}"'.format(filename), shell=True,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE).stdout.read()
    try:
        return x.decode()
    except:
        return x


def notify(title, subtitle, desc, alert_sound='Frog'):
    """
    Publish a notification to Notification Center:
        try the applescript method first, then the "objc" method

    note: 
        the applescript method only work with Mavericks (10.9) and later
        alert_sound: 'Frog','Blow', 'Pop' etc. or None

    """
    try:

        from Foundation import NSUserNotification
        from Foundation import NSUserNotificationCenter

        notification = NSUserNotification.alloc().init()
        center = NSUserNotificationCenter.defaultUserNotificationCenter()

        notification.setTitle_(title)
        notification.setInformativeText_(desc)
        notification.setSubtitle_(subtitle)
        if alert_sound is not None:
            # "NSUserNotificationDefaultSoundName"
            notification.setSoundName_(alert_sound)
        # notification.setIdentifier_('org.python.python3')
        center.deliverNotification_(notification)
        notification.dealloc()

    except Exception:

        try:

            if alert_sound is None:
                subprocess.Popen("""
                        osascript -e 'display notification "{}" with title "{}" subtitle "{}"'
                        """.format(desc, title, subtitle),
                                 shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
            else:
                subprocess.Popen("""
                        osascript -e 'display notification "{}" with title "{}" subtitle "{}" sound name "{}"'
                        """.format(desc, title, subtitle, alert_sound),
                                 shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()

        except Exception:
            pass


if __name__ == '__main__':

    main()
