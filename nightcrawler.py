#!/usr/bin/env python

# Nightcrawler - a web site offensive crawler

# https://www.freecodecamp.org/news/how-to-build-a-url-crawler-to-map-a-website-using-python-6a287be1da11/
# https://github.com/ahadsheriff/map-website/blob/master/map_website.py

import warnings
import requests.exceptions
import requests
import argparse
import sys
import coloredlogs, logging
from threading import Thread

from logging.handlers import WatchedFileHandler


from atpbar import atpbar
from collections import deque
from bs4 import BeautifulSoup
from urllib.parse import urlsplit
from urllib.parse import urlparse

__version__="0.1"
FORMATTER = logging.Formatter("%(asctime)s - [%(threadName)s] — %(name)s — %(levelname)s — %(message)s")
LOG_FILE = "nightcrawler.log"

def get_console_handler():
   console_handler = logging.StreamHandler(sys.stdout)
   console_handler.setFormatter(FORMATTER)
   return console_handler
def get_file_handler():
   file_handler = WatchedFileHandler(LOG_FILE)
   file_handler.setFormatter(FORMATTER)
   return file_handler

def get_logger(logger_name):
   logger = logging.getLogger(logger_name)
   logger.setLevel(logging.DEBUG) # better to have too much log than not enough
   logger.addHandler(get_console_handler())
   logger.addHandler(get_file_handler())
   # with this pattern, it's rarely necessary to propagate the error up to parent
   logger.propagate = False
   return logger

def crawler(url: str, ofile: str, count:int, form_pollution:bool, ignore_cert:bool, name:str) -> int:
    '''
    Crawl and pollute website
      
    Args:
        url (str): this is the starting point for the crawler.
        ofile (str): this is the optional report filename. If nil, only standard output will be used.
        count (int): each discovered url will be fetched 'count' times. This can be useful if we want to stress the endpoint. Default set to 1.
        form_pollution (bool): if set to True, the crawler will try to submit FORMs with bogus data. Default set to False.
        ignore_cert (bool): if set to True, the crawler won't check the SSL certificate. Default set to True
         
    Returns:
        crawler: the number of discovered URLs

    '''

    try: 

        new_urls = deque([url])
        processed_urls = set()
        local_urls = set()
        foreign_urls = set()
        broken_urls = set()

        s = requests.Session()
        s.verify=False

        while len(new_urls): 
            url = new_urls.popleft()    
            processed_urls.add(url) 
            my_logger.info("Processing %s" % url)

            # for x in range(0, count):
            for x in atpbar(range(0, count), name=name):
                my_logger.debug(".")
                try:    
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")
                        response = s.get(url)
                except(requests.exceptions.MissingSchema, requests.exceptions.ConnectionError, requests.exceptions.InvalidURL, requests.exceptions.InvalidSchema) as e:
                    broken_urls.add(url)    
                    my_logger.warning(url+" added to broken url")
                    my_logger.warning(str(e))
                    continue

            parts = urlsplit(url)
            base = "{0.netloc}".format(parts)
            strip_base = base.replace("www.", "")
            base_url = "{0.scheme}://{0.netloc}".format(parts)
            path = url[:url.rfind('/')+1] if '/' in parts.path else url


            soup = BeautifulSoup(response.text, "lxml")
            for link in soup.find_all('a'):    # extract link url from the anchor    
                anchor = link.attrs["href"] if "href" in link.attrs else ''
                if anchor.startswith('//'):
                    local_link = "{0.scheme}:".format(parts) + anchor
                    local_urls.add(local_link)    
                elif anchor.startswith('/'):        
                    local_link = base_url + anchor        
                    local_urls.add(local_link)    
                elif strip_base in anchor:        
                    local_urls.add(anchor)    
                elif not anchor.startswith('http'):        
                    local_link = path + anchor        
                    local_urls.add(local_link)    
                else:        
                    foreign_urls.add(anchor)
            for i in local_urls:    
                if not i in new_urls and not i in processed_urls:        
                    new_urls.append(i)

    except KeyboardInterrupt:
        sys.exit()

    return len(local_urls)

def main(argv):
    '''
    This is THE main

    Args:
        argv(Array): the command line
    Returns:
        main(int): returns 0 if everything worked as expected or -1 in case of errors
    '''

    text="A python program that crawls a website and tries to stress it, polluting forms with bogus data"
    parser = argparse.ArgumentParser(prog='nightcrawler', description=text, usage='%(prog)s [options]', epilog="Please make sure you're allowed to crawler and stress target website.")
    parser.add_argument('--url', '-u', required=True, help='the url you want to start to crawl from')
    parser.add_argument('--count', '-c', type=int, default=1, help='the number of times the crawler will get every url')
    parser.add_argument('--threads', '-t', type=int, default=1, help='the number of concurrents thread. Useful to stress test the website')
    parser.add_argument('--form-pollution', dest='pollution', action='store_true', help="pollute forms with bogus data")
    parser.add_argument('--no-form-pollution', dest='pollution', action='store_false', help="be fair with forms and not submit any data")

    parser.add_argument('--verbose', '-V', dest='verbose', action='store_true', help="be verbose")
    parser.set_defaults(pollution=False)
    parser.set_defaults(verbose=False)
    parser.add_argument('--version', action='version', version='%(prog)s {version}'.format(version=__version__))


    args = parser.parse_args()
    url = args.url
    count = args.count
    pollution = args.pollution 
    t = args.threads

    if args.verbose:
        my_logger.setLevel(logging.DEBUG)

    my_logger.debug(count)
    
    threads = []
    for ii in range(0, t):
        name='thread {}'.format(ii)
        process=Thread(target=crawler, args=[url, None, count, pollution, True, name])
        process.daemon = True
        process.start()
        threads.append(process)

    for process in threads:
        process.join()
    #crawler(url, None, count, pollution, True)

if __name__ == "__main__":
    my_logger=get_logger("nigthcrawler")
    my_logger.setLevel(logging.INFO)
    coloredlogs.install()
    main(sys.argv[1:])
        
