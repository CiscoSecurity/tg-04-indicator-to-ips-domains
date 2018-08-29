import os
import sys
import datetime
import ipaddress
import configparser
import requests
from IPy import IP

start = str(datetime.datetime.now())[:-7]


def sort_ip_list(ip_list):
    """Sort a list of IP address numerically"""
    return sorted(ip_list, 
      key=lambda ip:IP(ip).int())

def print_sid_ips():
    """Print the SID followed by list of unique IP address 1 per line"""
    for SID in ip_addresses_by_sample:
        print('\n',SID)
        for ip in ip_addresses_by_sample[SID]:
            print(' ',ip)

def print_sid_domains():
    """Print the SID followed by list of unique domains address 1 per line"""
    for SID in domains_by_sample:
        print('\n',SID)
        for domain in sorted(domains_by_sample[SID]):
            print(' ',domain)

def print_sid_domains_ips():
    """Print the SID followed by list of unique ips and domains address 1 per line"""
    for SID in ip_addresses_by_sample:
        print('\n',SID)
        for ip in ip_addresses_by_sample[SID]:
            print(' ',ip)
        for domain in sorted(domains_by_sample[SID]):
            print(' ',domain)

def print_all_ips():
    """Print all of the IPs found"""
    print('\nFound %d IP Addresses:' % len(ip_addresses))
    for ip in sort_ip_list(ip_addresses):
        print(' ',ip)

def print_all_domains():
    """Print all of the domains found"""
    print('\nFound %d domains:' % len(domains))
    for domain in sorted(domains):
        print(' ',domain)

def write_sample_info ():
    """
    Create a file in the results directory named with the HASH and timestamp
    Write the SID followed by a list of unique IPs and then unique domains
    that are associated with that sample
    """
    for hash in JSON_output:
        f = open('RESULTS/%s_%s_sample_info.txt' % (hash, timestamp),'w')
        for SID in JSON_output[hash]:
            f.write('\n%s\n' % SID)
            if JSON_output[hash][SID]['IPS'][0] == 'No External IP Addresses found':
                f.write('No External IP Addresses found\n')
            else:
                for IP in sort_ip_list(JSON_output[hash][SID]['IPS']):
                    f.write('%s\n' % IP)
            for Domain in sorted(JSON_output[hash][SID]['DOMAINS']):
                f.write('%s\n' % Domain)
        f.close()

def print_count_over_threshold():
    print('%s of the samples had a Threat Score greater than %s' % (len(sample_ids_scores),threashold))

def write_samples_over_threshold():
    with open('RESULTS/%s_%s_SIDS_over_%s.csv' % (intputFile_name, timestamp,threashold),'a') as checksumHit:
        for tup in sample_ids_scores:
            checksumHit.write('%s,%s\n' % (tup[0],tup[1]))

def write_samples_over_threshold_json():
    for hash in JSON_output:
        f = open('RESULTS/%s_%s_SIDS_over_%s.csv' % (intputFile_name, timestamp,threashold),'a')
        f.write('\n%s\n' % hash)
        for SID in JSON_output[hash]:
            SCORE = JSON_output[hash][SID]['THREATSCORE']
            if SCORE >= threashold:
                f.write('%s,%s\n' % (SID,SCORE))
        f.close()

def get( query ):
    try:
        r = session.get(query)
        if r.status_code // 100 != 2:
            return "Error: {}".format(r)
        return r.json()
    except requests.exceptions.RequestException as e:
        return 'Error Exception: {}'.format(e)

def errors( query ):
    if type(query) == str and query[:5] == 'Error':
        return True
    else:
        return False

def retry ( query, url ):
    # Check for errors and retry upto 3 times
    trim = 0
    retry_limit = 3
    while errors(query) == True and retry_limit > 0:
        # Write the error with time, error, and URL
        with open('Errors.txt','a') as f:
            f.write("{} {} - {}\n".format(start,query,url[trim:]))
        print('Error recieved retryining %s times' % retry_limit)
        # Retry the same query
        query = get(url)
        retry_limit -= 1
        # Exit after retrying 3 times
        if retry_limit == 0:
            with open('Errors.txt','a') as f:
                f.write("{} Error: Maximum Retry Reached - {}\n".format(start,url[trim:]))
                sys.exit()

def query_api ( query ):
    response = get(query)
    retry(response, query)
    return response

def paginate ( url ):
    # Container for results
    results = []

    # Setup parameters for pagination
    limit = 100
    returns = limit
    offset = 0
    total = 0

    # Loop to page through the results if the number of results is greater than the limit
    while returns >= limit:
        pagination_params = '&offset={}&limit={}'.format(offset,limit)
        query = query_api(url+pagination_params)
        results.append(query)
        returns = query['data']['current_item_count']
        total += returns
        offset += limit
    return results

# Validate a list of hashes was provided as an argument
if len(sys.argv) < 2:
    sys.exit('Usage:\n python %s hash_list.txt' % os.path.basename(__file__))

inputFile = sys.argv[1]

# Validate the provided list of hashes exists
if not os.path.isfile(str(inputFile)):
    sys.exit ('File %s doesn\'t exist' % inputFile)

# Specify the config file
configFile = 'api.cfg'

# Reading the config file to get settings
config = configparser.RawConfigParser()
config.read(configFile)

api_key = config.get('Main', 'api_key')
host_name = config.get('Main', 'host_name')

# Get the timestamp of when the script started
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H.%M.%S")

# Store the name of the file that contains the hashes
intputFile_name = os.path.basename(inputFile)

# Storage containers for ouput 
sample_ids = []
sample_ids_scores = []
ip_addresses = []
ip_addresses_by_sample = {}
domains = []
domains_by_sample = {}
hashMatches = []
JSON_output = {}
threashold = 70

session = requests.Session()

# Create RESULTS directory if it does not exist
if not os.path.exists('RESULTS'):
    os.makedirs('RESULTS')

# Count number of lines in inputFile
with open(inputFile,'r') as inputList:
    lines = sum(1 for line in inputList)

# Validate if each hash exists, if it does save all of the Sample IDs
with open(inputFile,'r') as inputList:
    line = 1
    for hash in inputList:
        hash = hash.strip()
        urlSearch = 'https://{}/api/v2/search/submissions?q={}&api_key={}'.format(host_name,hash,api_key)
        query = query_api(urlSearch)
        if query['data']['current_item_count'] is 0:
            print('Line %d of %d :-(' % (line,lines))
            with open('RESULTS/%s_%s_miss.txt' % (intputFile_name, timestamp),'a') as checksumMiss:
                checksumMiss.write('%s\n' % hash)
        else:
            JSON_output[hash] = {}
            print('Line %d of %d is a Winner! - %s' % (line,lines,hash))
            hashMatches.append(hash)
            with open('RESULTS/%s_%s_hits.txt' % (intputFile_name, timestamp),'a') as checksumHit:
                checksumHit.write('%s\n' % hash)
            for i in query['data']['items']:
                SID = i['item']['sample']
                if SID not in sample_ids:
                    sample_ids.append(SID)
                    JSON_output[hash][SID] = {'IPS': [], 'DOMAINS': [], 'THREATSCORE': 000}
        line += 1

# Print the number of hashes found
print('\nFound %d out of %d hashes in the system' % (len(hashMatches),lines))

# Print the number of samples found
print('\nFound %d samples from %d hashes:' % (len(sample_ids),len(hashMatches)))

# Query each Sample ID and get all of the IPs and Domains
for hash in JSON_output:
    current_hash = hash
    for SID in JSON_output[hash]:

        #/api/v2/samples/SID/analysis/network_streams?api_key=API_KEY
        urlNetworkStreams = 'https://{}/api/v2/samples/{}/analysis/network_streams?api_key={}'.format(host_name,SID,api_key)
        analysis_elements = query_api(urlNetworkStreams)
        network_streams = analysis_elements['data']['items']

        ip_addresses_by_sample[SID] = []
        domains_by_sample[SID] = []
        for stream in network_streams:
            dst_port = network_streams[stream]['dst_port']
            current_ip = network_streams[stream]['dst']
            # Verify traffic is to a public IP and add it to the list
            if IP(current_ip).iptype() == 'PUBLIC':
                if current_ip not in ip_addresses:
                    ip_addresses.append(current_ip)
                    with open('RESULTS/%s_%s_ips.txt' % (current_hash, timestamp),'a') as ipFound:
                        ipFound.write('%s\n' % current_ip)
                if current_ip not in ip_addresses_by_sample[SID]:
                    ip_addresses_by_sample[SID].append(current_ip)
                    JSON_output[current_hash][SID]['IPS'].append(current_ip)
            if dst_port == 53  and network_streams[stream]['protocol'] == 'DNS':
                option = network_streams[stream]['decoded']
                for keys in option:
                    current_domain = option[keys]['query']['query_data']
                    if current_domain != 'workstation':
                        if current_domain not in domains and current_domain != 'time.windows.com':
                            domains.append(current_domain)
                            with open('RESULTS/%s_%s_domains.txt' % (current_hash, timestamp),'a') as domainFound:
                                domainFound.write('%s\n' % current_domain)
                        if current_domain not in domains_by_sample[SID]:
                            domains_by_sample[SID].append(current_domain)
                            JSON_output[current_hash][SID]['DOMAINS'].append(current_domain)
        if len(ip_addresses_by_sample[SID]) == 0:
            no_ips = 'No External IP Addresses found'
            ip_addresses_by_sample[SID].append(no_ips)
            JSON_output[current_hash][SID]['IPS'].append(no_ips)
        if len(domains_by_sample[SID]) == 0:
            no_domains = 'No domains found'
            domains_by_sample[SID].append(no_domains)
            JSON_output[current_hash][SID]['DOMAINS'].append(no_domains)


print_all_ips()
print_all_domains()
write_sample_info()
