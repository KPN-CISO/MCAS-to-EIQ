#!/usr/bin/env python3

# (c) 2020 Arnim Eijkhoudt <arnime _squigglything_ kpn-cert.nl>

# This software is GPLv2 licensed, except where otherwise indicated

import argparse
import datetime
import json
import pprint
import socket
import time
import urllib
import ssl
import re

from eiqlib import eiqjson
from eiqlib import eiqcalls

from graphlib import graph

from config import settings


def transform(options, GRAPHTOKEN, sightings):
    '''
    Take the MCAS JSON object, extract all attributes into a list.
    '''
    if options.verbose:
        print("U) Converting MCAS Events into EIQ Sightings ...")
    try:
        if len(sightings) > 0:
            entityList = []
            for mcasEvent in sightings:
                eventID = mcasEvent['_id']
                entity = eiqjson.EIQEntity()
                entity.set_entity(entity.ENTITY_SIGHTING)
                entity.set_entity_source(settings.EIQSOURCE)
                tlp = 'amber'
                reliability = 'B'
                if 'timestamp' in mcasEvent:
                    timestamp = int(mcasEvent['timestamp'] / 1000)
                    observedtime = datetime.datetime.utcfromtimestamp(
                        timestamp).strftime("%Y-%m-%dT%H:%M:%SZ")
                entity.set_entity_tlp(tlp)
                entity.set_entity_reliability(reliability)
                title = mcasEvent['title']
                description = mcasEvent['description']
                confidence = entity.CONFIDENCE_MEDIUM
                classification = entity.CLASSIFICATION_UNKNOWN
                entity.set_entity_title(title + " - Event " +
                                        str(eventID) + " - " +
                                        settings.TITLETAG)
                entity.set_entity_observed_time(observedtime)
                entity.set_entity_description(description)
                entity.add_observable(entity.OBSERVABLE_URI,
                                      mcasEvent['URL'],
                                      classification=entity.CLASSIFICATION_GOOD,
                                      confidence=entity.CONFIDENCE_HIGH,
                                      link_type=entity.OBSERVABLE_LINK_OBSERVED)
                entity.set_entity_confidence(confidence)
                uuid = str(eventID) + '-MCAS'
                if 'entities' in mcasEvent:
                    '''
                    Try to find and extract all AD usernames from the description
                    '''
                    for addomainkey in settings.MCASADMAPPING:
                        searchtext = description.lower()
                        addomain = settings.MCASADMAPPING[addomainkey]
                        regex = ' (' + addomain + '\/[a-zA-Z0-9]+) '
                        pattern = re.compile(regex)
                        if (addomain+'/') in searchtext:
                            result = pattern.findall(searchtext)
                            for addomainusername in result:
                                addomainusername = addomainusername.replace('/','\\').lower()
                                eiqtype = entity.OBSERVABLE_HANDLE
                                link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                                classification = entity.CLASSIFICATION_UNKNOWN
                                handle = addomainusername
                                entity.add_observable(eiqtype,
                                                      handle,
                                                      classification=classification,
                                                      confidence=confidence,
                                                      link_type=link_type)
                    for mcasEntity in mcasEvent['entities']:
                        to_ids = False
                        eiqtype = False
                        if mcasEntity['type']:
                            type = mcasEntity['type']
                            name = mcasEntity['label']
                            confidence = entity.CONFIDENCE_MEDIUM
                            classification = entity.CLASSIFICATION_UNKNOWN
                            to_ids = False
                            eiqtype = False
                            if type == 'ip':
                                try:
                                    socket.inet_aton(name)
                                    eiqtype = entity.OBSERVABLE_IPV4
                                    to_ids = True
                                except socket.error:
                                    pass
                                try:
                                    socket.inet_pton(socket.AF_INET6, name)
                                    eiqtype = entity.OBSERVABLE_IPV6
                                    to_ids = True
                                except socket.error:
                                    pass
                            if type == 'user':
                                to_ids = True
                                if name.split('@')[1] in settings.MCASADMAPPING:
                                    email = name
                                    domain = settings.MCASADMAPPING[name.split('@')[1]]
                                    sslcontext = ssl.create_default_context()
                                    uri = settings.GRAPHURL + '/users/%s' % email
                                    uri += '?$select=OnPremisesSamAccountName,'
                                    uri += 'mail,'
                                    uri += 'businessPhones,mobilePhone'
                                    headers = {
                                        'Content-type': 'application/json',
                                        'Accept': 'application/json',
                                        'Authorization': 'Bearer %s' % GRAPHTOKEN,
                                    }
                                    request = urllib.request.Request(uri,
                                                                 headers=headers)
                                    if not settings.GRAPHSSLVERIFY:
                                        sslcontext.check_hostname = False
                                        sslcontext.verify_mode = ssl.CERT_NONE
                                    response = urllib.request.urlopen(request,
                                                                      context=sslcontext)
                                    jsonResponse = json.loads(response.read().decode('utf-8'))
                                    if options.verbose:
                                        print("U) Got a Graph API response:")
                                        print(jsonResponse)
                                    confidence = entity.CONFIDENCE_HIGH
                                    if 'onPremisesSamAccountName' in jsonResponse:
                                        eiqtype = entity.OBSERVABLE_HANDLE
                                        link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                                        classification = entity.CLASSIFICATION_UNKNOWN
                                        handle = domain + '\\' + jsonResponse['onPremisesSamAccountName'].lower()
                                        entity.add_observable(eiqtype,
                                                              handle,
                                                              classification=classification,
                                                              confidence=confidence,
                                                              link_type=link_type)
                                    if 'mail' in jsonResponse:
                                        eiqtype = entity.OBSERVABLE_EMAIL
                                        link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                                        classification = entity.CLASSIFICATION_UNKNOWN
                                        mail = jsonResponse['mail']
                                        if mail:
                                            entity.add_observable(eiqtype,
                                                                  mail,
                                                                  classification=classification,
                                                                  confidence=confidence,
                                                                  link_type=link_type)
                                    phones = []
                                    if 'businessPhones' in jsonResponse:
                                        if jsonResponse['businessPhones']:
                                            numbers = jsonResponse['businessPhones']
                                            if isinstance(numbers, list):
                                                for number in numbers:
                                                    phones.append(number)
                                            else:
                                                phones.append(numbers)
                                    if 'mobilePhone' in jsonResponse:
                                        if jsonResponse['mobilePhone']:
                                            numbers = jsonResponse['mobilePhone']
                                            if isinstance(numbers, list):
                                                for number in numbers:
                                                    phones.append(number)
                                            else:
                                                phones.append(numbers)
                                    if len(phones) > 0:
                                        for number in phones:
                                            eiqtype = entity.OBSERVABLE_TELEPHONE
                                            link_type = entity.OBSERVABLE_LINK_OBSERVED
                                            classification = entity.CLASSIFICATION_UNKNOWN
                                            entity.add_observable(eiqtype,
                                                                  number,
                                                                  classification=classification,
                                                                  confidence=confidence,
                                                                  link_type=link_type)
                            if type == 'account':
                                eiqtype = entity.OBSERVABLE_PERSON
                            if type == 'discovery_stream':
                                description = entity.get_entity_description()
                                newdescription = description + '<br />Usercategory: '
                                newdescription += name
                                entity.set_entity_description(newdescription)
                            if type == 'discovery_service':
                                description = entity.get_entity_description()
                                newdescription = description + '<br />Application: '
                                newdescription += name
                                entity.set_entity_description(newdescription)
                            if to_ids:
                                link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                                classification = entity.CLASSIFICATION_BAD
                            else:
                                link_type = entity.OBSERVABLE_LINK_OBSERVED
                            if eiqtype:
                                entity.add_observable(eiqtype,
                                                      name,
                                                      classification=classification,
                                                      confidence=confidence,
                                                      link_type=link_type)
                entityList.append((entity, uuid))
            return entityList
        else:
            if options.verbose:
                print("E) An empty result or other error was returned by " +
                      "MCAS. Enable verbosity to see the JSON result that " +
                      "was returned.")
    except KeyError:
        print("E) An empty JSON result or other error was returned " +
              "by MCAS:")
        print(sightings)
        raise


def eiqIngest(eiqJSON, uuid, options):
    '''
    Ingest the provided eiqJSON object into EIQ with the UUID provided
    (or create a new entity if not previously existing)
    '''
    if options.simulate:
        if options.verbose:
            print("U) Not ingesting anything into EIQ because the " +
                  "-s/--simulate flag was set.")
        return False

    if not settings.EIQSSLVERIFY:
        if options.verbose:
            print("W) You have disabled SSL verification for EIQ, " +
                  "this is not recommended.")

    eiqAPI = eiqcalls.EIQApi(insecure=not(settings.EIQSSLVERIFY))
    url = settings.EIQHOST + settings.EIQVERSION
    eiqAPI.set_host(url)
    eiqAPI.set_credentials(settings.EIQUSER, settings.EIQPASS)
    token = eiqAPI.do_auth()
    try:
        if options.verbose:
            print("U) Contacting " + url + ' to ingest ' + uuid + ' ...')
        if not options.duplicate:
            response = eiqAPI.create_entity(eiqJSON, token=token,
                                            update_identifier=uuid)
        else:
            response = eiqAPI.create_entity(eiqJSON, token=token)
    except IOError:
        raise
    if not response or ('errors' in response):
        if response:
            for err in response['errors']:
                print('[error %d] %s' % (err['status'], err['title']))
                print('\t%s' % (err['detail'], ))
        else:
            print('unable to get a response from host')
        return False
    else:
        return response['data']['id']


def download(options, MCASTOKEN):
    '''
    Download the given MCAS Event number from MCAS
    '''
    if options.verbose:
        print("U) Downloading MCAS Alerts ...")
    try:
        uri = settings.MCASURL
        headers = {
            'Accept': 'application/json',
            'Content-type': 'application/json',
            'Authorization': 'Token %s' % settings.MCASTOKEN,
        }
        endtime = int(time.time()) * 1000
        starttime = endtime - (int(options.window) * 1000)
        filters = {
            'date': {'gte': starttime}
        }
        body = {
            'filters': filters,
            'isScan': True,
        }
        sslcontext = ssl.create_default_context()
        if not settings.MCASSSLVERIFY:
            sslcontext.check_hostname = False
            sslcontext.verify_mode = ssl.CERT_NONE
        if options.verbose:
            print("U) Contacting " + uri + " ...")
        sightings = []
        has_next = True
        data = json.dumps(body).encode('utf-8')
        request = urllib.request.Request(uri,
                                         data=data,
                                         headers=headers)
        while has_next:
            reply = urllib.request.urlopen(request,
                                           context=sslcontext)
            jsonResponse = json.loads(reply.read().decode('utf-8'))
            response = jsonResponse.get('data', [])
            sightings += response
            has_next = jsonResponse.get('hasNext', False)
            body['filters'] = jsonResponse.get('nextQueryFilters')
        if options.verbose:
            print("U) Got an MCAS response:")
            pprint.pprint(sightings)
        return sightings
    except:
        if options.verbose:
            print("E) An error occured downloading MCAS sightings " +
                  "from " +
                  settings.MCASURL)
        raise


def main():
    parser = argparse.ArgumentParser(description='MCAS to EIQ converter')
    parser.add_argument('-v', '--verbose',
                        dest='verbose',
                        action='store_true',
                        default=False,
                        help='[optional] Enable progress/error info (default: disabled)')
    parser.add_argument('-w', '--window',
                        dest='window',
                        default=settings.MCASTIME,
                        help='[optional] Override time window of MCAS alerts to '
                             'download, specified in seconds. Default setting '
                             'from config file is: '+str(settings.MCASTIME))
    parser.add_argument('-t', '--type',
                        dest='type',
                        default='t',
                        help='[optional] Set the type of EclecticIQ entity you '
                             'wish to create: [t]tp (default), [s]ighting '
                             'or [i]ndicator. Not all entity types support all '
                             'observables/extracts! Nested objects in the MCAS '
                             'Event will be created as indicators and linked to '
                             'the TTP.')
    parser.add_argument('-s', '--simulate',
                        dest='simulate',
                        action='store_true',
                        default=False,
                        help='[optional] Do not actually ingest anything into '
                             'EIQ, just simulate everything. Mostly useful with '
                             'the -v/--verbose flag.')
    parser.add_argument('-n', '--name',
                        dest='name',
                        default=settings.TITLETAG,
                        help='[optional] Override the default TITLETAG name from '
                             'the configuration file (default: TITLETAG in'
                             'settings.py)')
    parser.add_argument('-d', '--duplicate',
                        dest='duplicate',
                        action='store_true',
                        default=False,
                        help='[optional] Do not update the existing EclecticIQ '
                             'entity, but create a new one (default: disabled)')
    args = parser.parse_args()
    sightings = download(args, settings.MCASTOKEN)
    if sightings:
        GRAPHTOKEN = graph.generateGraphToken(args, settings)
        if GRAPHTOKEN:
            entities = transform(args, GRAPHTOKEN, sightings)
            if entities:
                for entity, uuid in entities:
                    if args.verbose:
                        pprint.pprint(entity.get_as_json())
                    eiqIngest(entity.get_as_json(), uuid, args)
        else:
            print("U) No MCAS and/or GRAPH token available!")


if __name__ == "__main__":
    main()
