from webapp.tasks import attached_email, site_request, clean_url_string, init_var, lod_to_csv, lod_to_dol, fetch_proxies, rotate_proxies, output_checkmarks, href_all_links

from celery import shared_task
from webapp.celery import app, BaseTask

from bs4 import BeautifulSoup
import pandas as pd
import time
import requests

import argparse


@shared_task(name='Checkered_Master', base=BaseTask, soft_time_limit=6000)
def CK_Master_Iterate(inputList, inputRecipientEmail):

    output_lod = check_sites(inputList)

    if inputRecipientEmail:
        outputfilecsv = lod_to_csv(output_lod, f'Checkered {clean_url_string(inputList[0], True)}')
        attached_email.delay(outputfilecsv, inputRecipientEmail)
    else:
        output_dol = lod_to_dol(output_lod, {' ':['URL 1', 'Response Code', 'H1', 'H2', 'H3', 'HTML']})
        output_dol = output_checkmarks(output_dol)
        output_dol = href_all_links(output_dol)

        return output_dol

def check_sites(inputList):                        # Iterate through each site, checking for 200 or 404s
    output_lod = []
    proxies = fetch_proxies()                      # Get a list of proxies
    proxy = rotate_proxies(proxies, False, False)  # Take the first working one

    for n, website in enumerate(inputList):
        if pd.isnull(website):
            output_lod.append({"Input URL": "NaN", "Response Code": 0})
            continue

        output_dict = {'Input URL': website}
        website = clean_link(website)

        response = site_request(website, proxy, 0, "response", None, False)
        output_dict[f'Response Code'] = response.status_code
        print(response)
        print(response.status_code)
        if response.status_code in [200, 301, 302]:
            parsed = BeautifulSoup(response.content, 'lxml')
            output_dict['Website H1'] = fallback_find(parsed, "h1")
            output_dict['Website H2'] = fallback_find(parsed, "h2")
            output_dict['Website H3'] = fallback_find(parsed, "h3")
            # output_dict['Website HTML'] = str(parsed)

        output_lod.append(output_dict)

        if n % 25 == 0:
            proxy = rotate_proxies(proxies, False, False)

    print(output_lod)
    return output_lod


def clean_link(inputLink):
    url_string = clean_url_string(inputLink, False)
    return f'https://www.{url_string}'

def fallback_find(inputParsed, inputSelector):
    try:
        output_string = ""
        for item in inputParsed.findAll(inputSelector):
            item_text = item.text
            item_text = item_text.replace("\n","").strip()
            output_string += item_text + "/ "
        return output_string

    except Exception as e:
        print(e)
        return "None"