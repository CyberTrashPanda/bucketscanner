import boto3
from botocore.handlers import disable_signing
from botocore import UNSIGNED
from botocore.config import Config
import botocore
import logging
from sys import exit, version_info
import os.path

class s3scanner(object):

    def __init__(self):
        log_format = logging.Formatter("%(message)s") 
        sh = logging.StreamHandler()
        sh.setFormatter(log_format)

        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        logger.addHandler(sh)

        self.log = logger
        self.regionlist = None
        self.wordlist = None

    def read_wordlist(self, filename):
        try:
            fh = open(filename, 'r')
            data = fh.read()
            fh.close()
            self.wordlist = data.splitlines()
        except Exception as e:
            self.log.error("{}: {}".format(filename,str(e.args[1])))
            exit(0)
    
    def read_regionlist(self, filename):
        try:
            fh = open(filename, 'r')
            data = fh.read()
            fh.close()
        except Exception as e:
            self.log.error("{}: {}".format(filename,str(e.args[1])))
            exit(0)
        regions = data.splitlines()
        self.regionlist = list(filter(lambda x:x[0]!='#', regions))
    
    def extract_domain(self, url):
        if version_info >= (3, 0):
            from urllib.parse import urlparse
        elif version_info < (3, 0) and version_info >= (2, 5):
            from urlparse import urlparse
        return url.split('/')[2]

    def find_region_http(self, bucket_name):
        import requests
        for region in self.regionlist:
            url = "http://{}.s3-website.{}.amazonaws.com".format(bucket_name, region)
            try:
                res = requests.get(url)
                if res.status_code != 400:
                    return region
            except requests.exceptions.ConnectionError:
                next
        return None

    def find_region(self, bucket_name):
        s3 = boto3.resource('s3')
        bucket = s3.Bucket(bucket_name)
        s3.meta.client.meta.events.register(bucket_name, disable_signing)
        try:
            return s3.meta.client.head_bucket(Bucket=bucket_name)['ResponseMetadata']['HTTPHeaders']['x-amz-bucket-region']
        except botocore.exceptions.ClientError as e:
            return self.find_region_http(bucket_name)

    def check_bucket(self, bucket_name, region):
        bucket_exists = self.bucket_exists(bucket_name)
        if bucket_exists:
            region_name = self.find_region(bucket_name)
            if (region != None) and (region_name != region):
                self.log.info("[!] {} seems to be at region '{}' not '{}'.".format(bucket_name, region_name, region))
            elif region_name == None:
                self.log.info("[!] Could not determine the region for bucket '{}'.".format(bucket_name))
                return (bucket_name, True, "????", "????", "????")
            bucket_anon = self.bucket_open_anon(bucket_name, region_name)
            bucket_user = self.bucket_open_user(bucket_name, region_name)
            return (bucket_name, bucket_exists, region_name, bucket_anon, bucket_user)
        else:
            return (bucket_name, False, False, False, False)

    def parse_bucket_name(self, word):
        if "http" in word:
            #we got a url http://flaws.cloud
            bucket_name = self.extract_domain(word)
            return self.check_bucket(bucket_name, None)
        elif ":" in word:
            #we got a bucket name flaws.cloud:us-west-2
            bucket_name = word.split(":")[0]
            region_name = word.split(":")[1]
            return self.check_bucket(bucket_name, region_name)
        else:
            #we got a bucket name without region
            return self.check_bucket(word, None)

    def bucket_exists(self, bucket_name,region_name=None):
        if region_name:
            s3 = boto3.resource('s3', region_name=region_name)
        else:
            s3 = boto3.resource('s3')
        bucket = s3.Bucket(bucket_name)
        #s3.meta.client.meta.events.register(bucket_name, disable_signing)
        try:
            s3.meta.client.head_bucket(Bucket=bucket_name)
            return True
        except botocore.exceptions.ClientError as e:
            error_code = int(e.response['Error']['Code'])
            if error_code == 403:
                return True
            elif error_code == 404:
                return False

    def bucket_open_anon(self, bucket_name, region):
        s3 = boto3.resource('s3', region_name=region, config=Config(signature_version=UNSIGNED))
        bucket = s3.Bucket(bucket_name)
        try:
            s3.meta.client.head_bucket(Bucket=bucket_name)
            return True
        except botocore.exceptions.ClientError as e:
            return False

    def bucket_open_user(self, bucket_name, region, profile_name="default"):
        session = boto3.Session(profile_name=profile_name)
        s3 = session.resource('s3', region_name=region)
        bucket = s3.Bucket(bucket_name)
        try:
            s3.meta.client.head_bucket(Bucket=bucket_name)
            return True
        except botocore.exceptions.ClientError as e:
            return False

    def print_results(self, buckets):
        buckets_found = []
        buckets_notfound = []
        name_len = 0
        name_notfound_len = 0

        self.log.info("[+] Scanned {} bucket names.\n".format(len(buckets)))
        for bucket in buckets:
            if bucket[1]:
                if len(bucket[0]) > name_len:
                    name_len = len(bucket[0])
                buckets_found.append(bucket)
            else:
                if len(bucket[0]) > name_notfound_len:
                    name_notfound_len = len(bucket[0])
                buckets_notfound.append(bucket)

        if name_len < 30:
            border_size = 97 - (30 - name_len)
        else:
            border_size = 97 + (name_len - 30)
        border = "\t+{}+".format("-"*border_size)

        if len(buckets_found) > 0:
            self.log.info(border)
            self.log.info("\t| {:^{name_len}} | {:^16} | {:^20} | {:^20} |".format("Bucket", "Region", "Anonymous Access", "User Access", name_len=name_len))
            self.log.info(border)
            for bucket in buckets_found:
                self.log.info("\t| {:^{name_len}} | {:^16} | {:^20} | {:^20} |".format(bucket[0], bucket[2], str(bucket[3]), str(bucket[4]), name_len=name_len))
            self.log.info("{}\n".format(border))

        if len(buckets_notfound) > 0:
            if name_notfound_len < 30:
                border_size = 57 - (30 - name_notfound_len)
            else:
                border_size = 57 + (name_notfound_len - 30)

            border = "\t+{}+".format("-"*border_size)
            self.log.info(border)
            self.log.info("\t| {:^{name_len}} | {:^22} |".format("Bucket", "Result", name_len=name_notfound_len))
            self.log.info(border)
            for bucket in buckets_notfound:
                self.log.info("\t| {:^{name_len}} | {:^22} |".format(bucket[0], "404 (Bucket not found)", name_len=name_notfound_len))
            self.log.info(border)

    def check_creds(self):
        config = "{}/.aws/config".format(os.path.expanduser("~"))
        if os.path.isfile(config):    
            return True
        else:
            self.log.info("[!] AWS Credentials file not found.")
            self.log.info("[!] Make sure you run 'aws configure' to get proper results.")
            return False
        return

    def scan(self):
        buckets = []
        for bucket in self.wordlist:
            buckets.append(self.parse_bucket_name(bucket))
        self.print_results(buckets)
        return buckets
