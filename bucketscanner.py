#!/usr/vin/env python3

import s3func
import argparse
from sys import argv, exit

def banner():
    return """
                                .*/.
                               *((((*
                               /(((((*.
                               */*,...

                                                  .////*.
                                               .*//,...,/*
                                              ..       .//.
                        *//,.                          ,//.
                        .*(.   **.                     ((.
                              .(/.                   .*/.
                            .*/////*/*,.            .**
                               ..  .,(((*,.
                        ..   .*,.**    /(((*.
                   *,..*(/.    ,**.    ./((((*.
                   /(((((/               ./((((
                   /((((((*               .((((*.
                     .*(((((*,...           ./(*.
                         .//////**,,,,        .

                 Amazon S3 Bucket scanner by 'CyberTrashPanda'
          """


if __name__ == "__main__":
    global args
    if len(argv) == 1:
        print(banner())
    for i in argv:
        if i == "-h":
            print(banner())
    
    parser = argparse.ArgumentParser(description='A simple open s3 bucket scanner.')
    bucket_group = parser.add_mutually_exclusive_group(required=True)
    bucket_group.add_argument("-b", action="store", help="The name of the bucket to check", metavar=('bucket_name'), dest="bucket_name")
    bucket_group.add_argument("-B", action="store", help="The text file containing the bucket names.", metavar=('buckets.txt'), dest="bucket_file")
    parser.add_argument("-r","--regions", action="store", help="The text file containing the region names.", metavar=('regions.txt'), dest="regions_file", required=True)
    args = parser.parse_args()

    pwn = s3func.s3scanner()
    pwn.check_creds()
    if args.bucket_file:
        pwn.read_wordlist(args.bucket_file)
    elif args.bucket_name:
        pwn.wordlist = [args.bucket_name]
    pwn.read_regionlist(args.regions_file)
    try:
        pwn.scan()
    except KeyboardInterrupt:
        print("\n[!] Caught SIGINT exiting...")
        exit(0)
