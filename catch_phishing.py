#!/usr/bin/env python
# Copyright (c) 2017 @x0rz
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
import certstream
import psycopg2
import entropy

log_suspicious = 'suspicious_domains.log'

suspicious_keywords = [
    'login',
    'log-in',
    'account',
    'verification',
    'verify',
    'support',
    'activity',
    'security',
    'update',
    'authentication',
    'authenticate',
    'wallet',
    'alert',
    'purchase',
    'transaction',
    'recover',
    'live',
    'office'
    ]

highly_suspicious = [
    'paypal',
    'paypol',
    'poypal',
    'twitter',
    'appleid',
    'gmail',
    'outlook',
    'protonmail',
    'amazon',
    'facebook',
    'microsoft',
    'windows',
    'cgi-bin',
    'localbitcoin',
    'icloud',
    'iforgot',
    'isupport',
    'kraken',
    'bitstamp',
    'bittrex',
    'blockchain',
    '.com-',
    '-com.',
    '.net-',
    '.org-',
    '.gov-',
    '.gouv-',
    '-gouv-'
    ]

suspicious_tld = [
    '.ga',
    '.gq',
    '.ml',
    '.cf',
    '.tk',
    '.xyz',
    '.pw',
    '.cc',
    '.club',
    '.work',
    '.top',
    '.support',
    '.bank',
    '.info',
    '.study',
    '.party',
    '.click',
    '.country',
    '.stream',
    '.gdn',
    '.mom',
    '.xin',
    '.kim',
    '.men',
    '.loan',
    '.download',
    '.racing',
    '.online',
    '.ren',
    '.gb',
    '.win',
    '.review',
    '.vip',
    '.party',
    '.tech',
    '.science'
    ]

def score_domain(domain):
    """Score `domain`.

    The highest score, the most probable `domain` is a phishing site.

    Args:
        domain (str): the domain to check.

    Returns:
        int: the score of `domain`.
    """
    score = 0
    for tld in suspicious_tld:
        if domain.endswith(tld):
            score += 20
    for keyword in suspicious_keywords:
        if keyword in domain:
            score += 25
    for keyword in highly_suspicious:
        if keyword in domain:
            score += 60
    score += int(round(entropy.shannon_entropy(domain)*50))

    # Lots of '-' (ie. www.paypal-datacenter.com-acccount-alert.com)
    if 'xn--' not in domain and domain.count('-') >= 4:
        score += 20
    return score


def callback(message, context):
    """Callback handler for certstream events."""
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        for domain in all_domains:
            score = score_domain(domain)
            if score > 75:
                print(str(domain) + "," + str(score) + ",Suspicious")
                insert_domain(str(domain), score, "Suspicious")
            elif score > 65:
                print(str(domain) + "," + str(score) + ",Potential")
                insert_domain(str(domain), score, "Potential")

def insert_domain(url, score, category):
    print("inserting into db")
    sql = """INSERT INTO phishy_sites(url,score,category) VALUES(%s, %s, %s);"""
    try:
        #conn = psycopg2.connect(host="ec2-184-73-247-240.compute-1.amazonaws.com", database="ddu0j66qdb2qf0", user="kkimbrfqqymfoc", password="b39ef8625e78b731ab19c3050b0f50b602abd9b908990171f99a4f6e44b26682", port=5432)
        conn = psycopg2.connect(host="ec2-54-225-192-243.compute-1.amazonaws.com",
                        database="d50rrv49epp2mb", user="csqxrzedqjfkbr",
                        password="77135a5f0f9db7906f620ab209b2cbb00d9fb80ceecfa2e2b26ff5800319ea30",
                        port=5432)
        cur = conn.cursor()
        cur.execute(sql, (url,score,category))
        conn.commit()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
    finally:
        if conn is not None:
            conn.close()

certstream.listen_for_events(callback)
