# -*- coding: utf-8 -*-
# pylint: disable=C0103
# pylint: disable=C0111
# pylint: disable=C0301
# pylint: disable=W0311

##  Credit for original build to si9int  ##
## https://github.com/si9int/cc.py ##

from celery import shared_task, group
from webapp.celery import app, BaseTask
from webapp.tasks import attached_email, clean_url_string, href_all_links, lol_to_dol
from datetime import datetime
import pandas as pd
import requests
import json

def custom_clean_url_string(inputURL):
    if "://" in inputURL:
        inputURL = inputURL.split("://", 1)[1]
    if "www." in inputURL:
        inputURL = inputURL.split("www.", 1)[1]
    return inputURL

def prepare_timestamp(inputTimestamp):
    clean_time = datetime(year=int(inputTimestamp[0:4]), month=int(inputTimestamp[4:6]), day=int(inputTimestamp[6:8]))
    return datetime.strftime(clean_time, '%m.%d.%y')

@shared_task(name='Sitemapper_Indexing', base=BaseTask)
def query_indexes(index, inputURL):
    print('[-] Getting: ' + index)
    data = requests.get('http://index.commoncrawl.org/' + index + '-index?url=*.' + inputURL + '&output=json')
    data = data.text.split('\n')[:-1]

    return data

@shared_task(name='Sitemapper_Cleaning', base=BaseTask)
def clean_links(inputRawDataLoJ):
    link_lol = []

    for i, entry in enumerate(inputRawDataLoJ):
        for link in entry:
            try:
                output_link = custom_clean_url_string(json.loads(link)['url'])

                if output_link and not any(link[0] == output_link for link in link_lol):

                    timestamp = prepare_timestamp(json.loads(link)['timestamp'])
                    status = json.loads(link).get('status', "")
                    length = json.loads(link).get('length', "")
                    languages = json.loads(link).get('languages', "")
                    link_lol.append([output_link, status, timestamp, length, languages])


            except Exception as e:
                print(e)


        # Print progress of extracting structured link data. This is mostly for the [X] export option
        if i % 3 == 0 and i != 0:
            print("[*] We are " + str((float(i)/len(inputRawDataLoJ))*100) + "%% done.")

    return link_lol


@shared_task(name='Sitemapper_Master', base=BaseTask, soft_time_limit=1200)
def SM_Master_Iterate(inputURL, inputRecipientEmail):

    indexes = [
        'CC-MAIN-2019-13',
        'CC-MAIN-2019-09',
        'CC-MAIN-2019-04',
        'CC-MAIN-2018-51',
        'CC-MAIN-2018-47',
    ]
    extended_indexes = [
        'CC-MAIN-2018-43',
        'CC-MAIN-2018-39',
        'CC-MAIN-2018-34',
        'CC-MAIN-2018-30',
        'CC-MAIN-2018-26',
        'CC-MAIN-2018-22',
        'CC-MAIN-2018-17',
        'CC-MAIN-2018-13',
        'CC-MAIN-2018-09',
        'CC-MAIN-2018-05',
        'CC-MAIN-2017-51',
        'CC-MAIN-2017-47',
        'CC-MAIN-2017-43',
        'CC-MAIN-2017-39',
        'CC-MAIN-2017-34',
        'CC-MAIN-2017-30',
        'CC-MAIN-2017-26',
        'CC-MAIN-2017-22',
        'CC-MAIN-2017-17',
        'CC-MAIN-2017-13',
        'CC-MAIN-2017-09',
        'CC-MAIN-2017-04',
        'CC-MAIN-2016-50',
        'CC-MAIN-2016-44',
        'CC-MAIN-2016-40',
        'CC-MAIN-2016-36',
        'CC-MAIN-2016-30',
        'CC-MAIN-2016-26',
        'CC-MAIN-2016-22',
        'CC-MAIN-2016-18',
        'CC-MAIN-2016-07',
        'CC-MAIN-2015-48',
        'CC-MAIN-2015-40',
        'CC-MAIN-2015-35',
        'CC-MAIN-2015-32',
        'CC-MAIN-2015-27',
        'CC-MAIN-2015-22',
        'CC-MAIN-2015-18',
        'CC-MAIN-2015-14',
        'CC-MAIN-2015-11',
        'CC-MAIN-2015-06',
        'CC-MAIN-2014-52',
        'CC-MAIN-2014-49',
        'CC-MAIN-2014-42',
        'CC-MAIN-2014-41',
        'CC-MAIN-2014-35',
        'CC-MAIN-2014-23',
        'CC-MAIN-2014-15',
        'CC-MAIN-2014-10',
        'CC-MAIN-2013-48',
        'CC-MAIN-2013-20'
        ]

    # To handle the multiple JSON objects, we append them to a list to make a List of JSOn
    raw_data_loj = []
    outputfilecsv = "Mapped: " + clean_url_string(inputURL, True)

    # If the user wants the result displayed in the GUI:
    if not inputRecipientEmail:

        for index in indexes:
            raw_data_loj.append(query_indexes(index, inputURL))

        output_lol = clean_links(raw_data_loj)

        output_dol = lol_to_dol(output_lol)

        return href_all_links(output_dol)

    # If the user is willing to wait for the file to be emailed, we can run a much longer list
    # without worrying about the 30s web dyno timeout. Here we will reverse the list of indicies
    # so the timestamp represents the _first_ time a page was found, rather than the _most recent_
    else:
        combined_indexes = indexes + extended_indexes
        combined_indexes.reverse()

        for index in combined_indexes:
            raw_data_loj.append(query_indexes(index, inputURL))

        output_lol = clean_links(raw_data_loj)

        df = pd.DataFrame(output_lol)
        df.to_csv(outputfilecsv, index=False, sep=',')

        attached_email.delay(outputfilecsv, inputRecipientEmail)
