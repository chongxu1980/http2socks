#!/usr/bin/python3
# -*- coding: UTF-8 -*-

import logging
logging.basicConfig(level=logging.DEBUG,
                format='%(asctime)s [line:%(lineno)d] %(levelname)s %(message)s',
                datefmt='%M:%S',
                )
import asyncio
import argparse
import re
import socks
import traceback

TUNNEL_OK = '''HTTP/1.1 200 Connection Established\r\nProxy-Connection: close\r\n\r\n'''
BUFF = 1024

def get_sock(address):
    sock = socks.socksocket()
    sock.set_proxy(socks.SOCKS5, *socks_address)
    sock.connect(address)
    return sock

def parse_command_line(description):
        """Parse command line and return a socket address."""
        parser = argparse.ArgumentParser(description=description)
        parser.add_argument('-H', metavar='host', type=str, default='127.0.0.1', help='IP or hostname for http_proxy (default "127.0.0.1")', )
        parser.add_argument('-P', metavar='port', type=int, default=18080, help='port for http_proxy (default 18080)')
        parser.add_argument('-sh', metavar='socks_host', type=str, default='127.0.0.1', help='socks_proxy IP or hostname (default "127.0.0.1")')
        parser.add_argument('-sp', metavar='socks_port', type=int, default=1080, help='socks_proxy port (default 1080)')
        args = parser.parse_args()
        address = (args.H, args.P)
        socks_address = (args.sh, args.sp)

        return address, socks_address

    
def parse_request_header(header):
    '''
    parse http request header,
    return (host, port, method, uri, headers) when success
    return (None, None, None, None, None) when fail
    '''
    logging.debug('header: {}'.format(header))
    lines = header.strip().split('\r\n')
    logging.debug('lines: {}'.format(lines))
    try:
        '''parse method and uri'''
        line0 = lines[0].split(' ')
        method = line0[0].upper()
        uri = line0[1]

        '''parse other header'''
        headers = {}
        for i in range(1, len(lines)):
            line = lines[i].split(':')
            key = line.pop(0)
            value = ''.join(line)
            headers[key] = value.strip()

        '''deal with host and port'''
        if method in ['CONNECT']:
            target_host_and_port = uri.split(':')
        else:
            target_host_and_port = headers['Host'].split(':')
        if len(target_host_and_port) == 1:
            target_host = target_host_and_port[0]
            if method in ['CONNECT']: target_port = 443
            else: target_port = 80
        else:
            target_host = target_host_and_port[0]
            target_port = int(target_host_and_port[1].strip())
    except Exception as err:
        logging.error(err)
        return None, None, None, None, None
    logging.info('parse request completed')
    return target_host, target_port, method, uri, headers

def parse_response_header(response_header):
    '''parse http response'''
    Transfer_Encoding = False
    Content_Length = 0
    status_code = 0
    lines = response_header.strip().split('\r\n')
    status_code = int(lines[0].split(' ')[1])

    headers = {}
    for i in range(1, len(lines)):
        line = lines[i].split(':')
        key = line.pop(0)
        value = ''.join(line)
        headers[key] = value.strip()

    logging.info('parse response completed')
    return status_code, headers

async def do_proxy(host, port, method, uri, request_headers, request, reader, writer):
    try:
        sock = get_sock((host, port))
        remote_reader, remote_writer = await asyncio.open_connection(sock=sock)
        logging.info('connected {} {}'.format(host, port))
    except Exception as err:
        logging.error('connection error {}:{}'.format(host, port))
        writer.write(str(err).encode('ascii'))
        writer.close()
        return
    try:
        remote_writer.write(request)
        logging.debug("Write request success.")
        response = b''
        got_header = False
        headers = {}
        while True:
            buf = await remote_reader.read(BUFF)
            response += buf
            writer.write(buf)
            logging.debug('read/write buf success')
            if not got_header and '\r\n\r\n'.encode('ascii') in response:
                got_header = True
                logging.debug('set got header')
                response_header = (response.split('\r\n\r\n'.encode('ascii'))[0] + '\r\n\r\n'.encode('ascii')).decode('ascii')
                header_length = len(response_header)
                logging.debug('response_header is {}'.format(response_header))
                status_code, headers = parse_response_header(response_header)
                logging.debug('status_code is {}'.format(status_code))
                logging.debug('headers is {}'.format(headers))

            if got_header:
                ''' return header when nothing responsed '''
                if method in ['HEAD']:
                    break
                if method in ['GET', 'POST']:
                    if status_code in [204, 301, 302, 303, 304, 307]:
                        break
                    if 'Transfer-Encoding' in headers:
                        if not buf:
                            logging.debug('not buf in transfer-encoding')
                            break
                    if 'Content-Length' in headers:
                        if int(headers['Content-Length']) <= len(response) - header_length:
                            break
                    if not 'Content-Length' in headers and not 'Transfer-Encoding' in headers and not buf:
                        logging.debug('not buf')
                        break
    except Exception as err:
        traceback.print_exc()
        writer.close()
        remote_writer.close()
        return

async def write_to(reader, writer):
    while True:
        try:
            buf = await reader.read(BUFF)
            if not buf:
                writer.close()
                break
            writer.write(buf)
            await writer.drain()
        except Exception as err:
            logging.error(err)
            break

async def do_tunnel(host, port, reader, writer):
    try:
        sock = get_sock((host, port))
        remote_reader, remote_writer = await asyncio.open_connection(sock=sock)
        logging.info('connected to {} {}'.format(host, port))
    except Exception as err:
        logging.error('connect err {}:{}'.format(host, port))
        writer.write(TUNNEL_FAIL.encode('ascii'))
        writer.close()
        return
    writer.write(TUNNEL_OK.encode('ascii'))
    remote_to_local_t = asyncio.create_task(write_to(remote_reader, writer))
    local_to_remote_t = asyncio.create_task(write_to(reader, remote_writer))
    await asyncio.gather(
        remote_to_local_t,
        local_to_remote_t
    )

async def handle_connection(reader, writer):
    request = b''
    got_header = False
    while True:
        buf = await reader.read(BUFF)
        request += buf
        if not got_header and '\r\n\r\n'.encode('ascii') in request:
            got_header = True
            request_header = (request.split('\r\n\r\n'.encode('ascii'))[0] + '\r\n\r\n'.encode('ascii')).decode('ascii')
            header_length = len(request_header)
            host, port, method, uri, headers = parse_request_header(request_header)
            logging.debug('host: {}, port:{}'.format(host, port))
            if not host or not port or not method in ['HEAD', 'GET', 'POST', 'CONNECT']:
                logging.warning('parser request err or method not support, close this task')
                writer.close()
                break
            if method in ['GET', 'HEAD', 'CONNECT']:
                break
        if got_header and method in ['POST']:
            if 'Content-Length' in headers:
                if int(headers['Content-Length']) <= len(request) - header_length:
                    break
            else:
                logging.warning('no Content-Length in POST request, close this task')
                writer.close()
                break
        if not buf:
            break
    if not '\r\n\r\n'.encode('ascii') in request:
        logging.warning('request err, close this task')
        writer.close()
    if method in ['GET', 'POST', 'HEAD']:
        request_header = re.sub('Proxy-Connection: .+\r\n', '', request_header)
        request_header = re.sub('Connection: .+', '', request_header)
        request_header = re.sub('\r\n\r\n', '\r\nConncetion: close\r\n\r\n', request_header)
        request = request_header.encode('ascii') + request[header_length:]

    if method in ['CONNECT']:
        await do_tunnel(host, port, reader, writer)
    else:
        await do_proxy(host, port, method, uri, headers, request, reader, writer)


async def main(address):
    server = await asyncio.start_server(
            handle_connection, *address)

    addr = server.sockets[0].getsockname()
    logging.info('Listening at {}'.format(addr))
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    global socks_address
    address, socks_address = parse_command_line('simple socks server')
    asyncio.run(main(address))
