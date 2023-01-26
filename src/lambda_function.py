import json
import os
import re
import pycurl
from aws_lambda_powertools import Logger
from io import BytesIO, StringIO
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from crhelper import CfnResource

ENV_URL = 'URL'
ENV_LOGZIO_TOKEN = 'LOGZIO_LOG_SHIPPING_TOKEN'
ENV_LISTENER = 'LOGZIO_LISTENER'
ENV_TYPE = 'LOGZIO_TYPE'
ENV_FIELDS = 'LOGZIO_FIELDS'
DEFAULT_TYPE = 'synthetic-links-detector'
DEFAULT_LISTENER = 'https://listener.logz.io:8071'
URL = os.getenv(ENV_URL, '')
TOKEN = os.getenv(ENV_LOGZIO_TOKEN, '')
TYPE = os.getenv(ENV_TYPE, DEFAULT_TYPE)
LISTENER = os.getenv(ENV_LISTENER, DEFAULT_LISTENER)
CUSTOM_FIELDS = {}

# set logger
logger = Logger()

# for first invocation
helper = CfnResource()


# Validate required parameters
def validate():
    if URL == '':
        raise ValueError('Missing URL. Exiting.')
    if TOKEN == '':
        raise ValueError('Missing Logz.io shipping token. Exiting.')


# Get tags from user, if applicable
def get_tags():
    global CUSTOM_FIELDS
    tags_str = os.getenv(ENV_FIELDS, '')
    if tags_str != '':
        tags_pairs = tags_str.split(',')
        for pair in tags_pairs:
            key_val = pair.split('=')
            CUSTOM_FIELDS[key_val[0]] = key_val[1]


# Scrape url for links
def get_links_from_url():
    try:
        links = []
        storage = BytesIO()
        c = pycurl.Curl()
        c.setopt(c.URL, URL)
        c.setopt(c.WRITEFUNCTION, storage.write)
        c.setopt(pycurl.FOLLOWLOCATION, 1)
        custom_headers = [
            'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36']
        c.setopt(pycurl.HTTPHEADER, custom_headers)
        c.perform()
        c.close()
        content = storage.getvalue().decode('utf-8')
        html_txt = BeautifulSoup(content, features='html.parser')
        for link in html_txt.findAll('a'):
            try:
                href = link.get('href')
                if href is not None:
                    # Some links are relative. If so - we build the link by concatenating the relative path to the
                    # giver url
                    if not re.search(r'^http(s?):\/\/', href):
                        href = f'{URL}{href}'
                    if href not in links:
                        links.append(href)
            except Exception as e:
                logger.warning(f'Error while processing tag {link}: {e}. Skipping')
        return links
    except Exception as e:
        logger.error(f'Encountered error while collecting page\'s links: {e}')
        return link


# Getting network data from url
def extract_info(url):
    try:
        c = pycurl.Curl()
        c.setopt(pycurl.URL, url)  # set url
        c.setopt(pycurl.FOLLOWLOCATION, 1)
        c.setopt(pycurl.WRITEFUNCTION, lambda x: None)
        custom_headers = [
            'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/109.0.0.0 Safari/537.36']
        c.setopt(pycurl.HTTPHEADER, custom_headers)
        c.perform()
        dns_time = c.getinfo(pycurl.NAMELOOKUP_TIME) * 1000  # DNS time
        conn_time = c.getinfo(pycurl.CONNECT_TIME) * 1000  # TCP/IP 3-way handshaking time
        starttransfer_time = c.getinfo(pycurl.STARTTRANSFER_TIME) * 1000  # time-to-first-byte time
        ssl_time = c.getinfo(pycurl.APPCONNECT_TIME) * 1000  # ssl
        send_time = c.getinfo(pycurl.PRETRANSFER_TIME) * 1000  # send time
        total_time = c.getinfo(pycurl.TOTAL_TIME) * 1000  # last request time
        port = c.getinfo(pycurl.PRIMARY_PORT)  # port
        status_code = c.getinfo(pycurl.HTTP_CODE)
        c.close()
        add_logzio_att_and_send({'link': url,
                                 'main_url': URL,
                                 'status_code': str(status_code),
                                 'dns_time': dns_time,
                                 'connect_time': conn_time,
                                 'start_transfer_time': starttransfer_time,
                                 'ssl_time': ssl_time,
                                 'send_time': send_time,
                                 'port': port,
                                 'total_time': total_time})
    except Exception as e:
        logger.error(f'Error while extracting info from link {e}')


# Add logzio parameters to the log
def add_logzio_att_and_send(log):
    log['type'] = TYPE
    if len(CUSTOM_FIELDS) > 0:
        log.update(CUSTOM_FIELDS)
    send_to_logzio(log)


# Send log to logzio
def send_to_logzio(log):
    max_retry = 4
    retry = 1
    c = pycurl.Curl()
    c.setopt(pycurl.URL, f'{LISTENER}?token={TOKEN}')
    c.setopt(pycurl.HTTPHEADER, ['Content-Type: application/json'])
    c.setopt(pycurl.POST, 1)
    c.setopt(pycurl.TIMEOUT_MS, 3000)
    c.setopt(pycurl.WRITEFUNCTION, lambda x: None)
    body_str = json.dumps(log)
    body = StringIO(body_str)
    c.setopt(pycurl.READDATA, body)
    c.setopt(pycurl.POSTFIELDSIZE, len(body_str))
    try:
        while retry < max_retry:
            c.perform()
            status_code = c.getinfo(pycurl.RESPONSE_CODE)
            if status_code == 200:
                break
            elif status_code == 400:
                logger.warning(f'Got {status_code} for {log}, bad request, log will not be sent')
                break
            elif status_code == 401:
                logger.error(f'Got {status_code}, unauthorized, please check your Logz.io token')
                break
            elif 400 < status_code < 500:
                logger.warning(f'Got {status_code} for {log}. Log will not be sent')
                break
            else:
                logger.warning(f'Got {status_code}')
                retry += 1
                if retry < max_retry:
                    logger.warning(f'Will retry sending')

    except Exception as e:
        logger.warning(f'Error while trying to send log: {e}')
    finally:
        c.close()


@helper.create
@helper.update
def detect(event, context):
    validate()
    get_tags()
    links = get_links_from_url()
    logger.info(f'Found {len(links)} links')
    with ThreadPoolExecutor(max_workers=len(links)) as executor:
        executor.map(extract_info, links)
    helper.Data['Message'] = 'Finished custom resource run'


@helper.delete
def no_op(_, __):
    pass


def lambda_handler(event, context):
    if 'RequestId' in event and event['RequestId'] != '':
        helper(event, context)
    else:
        validate()
        get_tags()
        links = get_links_from_url()
        logger.info(f'Found {len(links)} links')
        with ThreadPoolExecutor(max_workers=len(links)) as executor:
            executor.map(extract_info, links)
