#!/bin/env python
# -*- coding: utf-8 -*-

#
# Copyright (C) 2012 Alexander Labunets (cahbka@gmail.com).
# All rights reserved.
#

import logging
import M2Crypto
import urllib
import urllib2
import xml.etree.ElementTree as etree

class SPGW:
    ALG = 'SHA1RSA'

    def __init__(self, private_key, public_key, url, aid, tident):
        self.private_key = private_key
        self.public_key = public_key
        self.url = url
        self.aid = aid
        self.tident = tident

    def _sign(self, text):
        key = M2Crypto.EVP.load_key_string(self.private_key)
        key.reset_context(md='sha1')
        key.sign_init()
        key.sign_update(text)
        signature = key.sign_final()[::-1]              # compatibility with Microsoft Cryptographic API (CAPI)
        return signature.encode('base64')

    def _verify_sign(self, text, signature):
        signature = signature.decode('base64')[::-1]    # compatibility with Microsoft Cryptographic API (CAPI)
        bio = M2Crypto.BIO.MemoryBuffer(self.public_key)
        rsa = M2Crypto.RSA.load_pub_key_bio(bio)
        pubkey = M2Crypto.EVP.PKey()
        pubkey.assign_rsa(rsa)
        pubkey.reset_context(md='sha1')
        pubkey.verify_init()
        pubkey.verify_update(text)
        return pubkey.verify_final(signature)

    def _parse(self, response):
        root = etree.fromstring(response)
        self.c = int(root.find('C').text.encode('utf-8'))
        self.r = root.find('R').text.encode('utf-8')
        self.s = root.find('S').text.encode('utf-8')
        if self._verify_sign(self.r, self.s):
            logging.debug('The signature is authentic')
            return dict(x.split('=') for x in self.r.split('&'))
        else:
            logging.debug('The signature is not authentic')
            return None

    def _send(self, command, params):
        query = 'ot=%s' % command
        for k, v in params.items():
            query = '&'.join([query, '='.join([k, v])])
        signature = self._sign(query)
        request = '{0:>s}?alg={1:>s}&query={2:>s}&sign={3:>s}'.format(
            self.url,
            self.ALG,
            urllib2.quote(query.encode('cp1251')),
            urllib2.quote(signature)
        )
        logging.debug("Request: [{0:>s}]".format("".join(request.split())))
        response = urllib2.urlopen(request).read()
        logging.debug("Response: [{0:>s}]".format("".join(response.split())))
        return self._parse(response)

    def request(self, ocode, code_1, code_2, code_3, amount, full_amount):
        command = 'R'
        params = {'TIdent': str(self.tident),
                  'OCode' : str(ocode),
                  'Code1' : str(code_1),
                  'Code2' : str(code_2),
                  'Code3' : str(code_3),
                  'Amount' : str(int(amount * 100)),
                  'FullAmount' : '' if full_amount is None else str(int(full_amount * 100))}
        return self._send(command, params)

    def confirm(self, cid, receiptnum):
        command = 'C'
        params = {'TIdent': str(self.tident),
                  'Cid': str(cid),
                  'ReceiptNum': str(receiptnum)}
        return self._send(command, params)

    def balance(self):
        command = 'GB'
        params = {'AId': str(self.aid)}
        balance = None
        try:
            b = self._send(command, params).get("Balances", None)
            if b:
                root = etree.fromstring(urllib.unquote_plus(b))
                node = root.find('Balance').find('CurrentBalance')
                if node.text:
                    balance = node.text
        except:
            pass
        return balance

if __name__ == "__main__":
    # set logger
    channel = logging.StreamHandler()
    channel.setFormatter(logging.Formatter("[%(asctime)s] [%(process)d] [%(levelname)-8s] %(message)s"))
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(channel)

    url = 'https://test.delta-telecom.ru/dtpayspgw/'

    # agent params
    privkey = open("private.key").read()
    pubkey = open("pubkey.pem").read()
    aid = 5088
    tident = '00000005088.00001558'

    # payment params
    receiptnum = '123456789'
    ocode = 3
    code_1 = '9261234567'
    amount = 97.0
    full_amount = 100.0

    # start test
    spgw = SPGW(privkey, pubkey, url, aid, tident)
    balance = spgw.balance()
    if balance and spgw.c == 0:
        balance = float(balance)
        logging.info("Balance = {0:.2f}".format(balance))
        if balance > amount:
            response = spgw.request(ocode, code_1, '', '', amount, full_amount)
            if spgw.c == 0:
                result = int(response.get("Result", None))
                message = response.get("ResultMessage", None)
                logging.info("Result = {0:>d}, Message = {1:>s}".format(result, message))
                if result == 0 and spgw.c == 0:
                    cid = int(response["Cid"])
                    response = spgw.confirm(cid, receiptnum)
                    if spgw.c == 0:
                        result = int(response.get("Result", None))
                        logging.info("Result = {0:>d}, Cid = {1:>d}".format(result, cid))
                        if result == 0:
                            logging.info("Payment processed successfully")
                else:
                    logging.info("Payment error: {0:>s}".format(message))
            else:
                logging.error("Error: {0:>s}".format(spgw.r))
        else:
            logging.error("Error: balance too low")
    else:
        logging.error("Error: wrong balance ({0:>s})".format(spgw.r))
