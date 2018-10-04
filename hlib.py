
def dictionaryattack(txtName):
    txt = open(txtName,'r')
    dictionary = list()
    while 1: 
      word = txt.readline()
      if len(word) == 0:
         break
      dictionary.append(word.strip())
    txt.close()
    return dictionary

def parseHeader(buff, type='response'):
    import re
    SEP = '\r\n\r\n'
    HeadersSEP = '\r*\n(?![\t\x20])'
    import logging
    log = logging.getLogger('parseHeader')
    if SEP in buff:
        header, body = buff.split(SEP, 1)
    else:
        header = buff
        body = ''
    headerlines = re.split(HeadersSEP, header)

    if len(headerlines) > 1:
        r = dict()
        if type == 'response':
            _t = headerlines[0].split(' ', 2)
            if len(_t) == 3:
                sipversion, _code, description = _t
            else:
                log.warn('Could not parse the first header line: %s' % `_t`)
                return r
            try:
                r['code'] = int(_code)
            except ValueError:
                return r
        elif type == 'request':
            _t = headerlines[0].split(' ', 2)
            if len(_t) == 3:
                method, uri, sipversion = _t
        else:
            log.warn('Could not parse the first header line: %s' % `_t`)
            return r
        r['headers'] = dict()
        for headerline in headerlines[1:]:
            SEP = ':'
            if SEP in headerline:
                tmpname, tmpval = headerline.split(SEP, 1)
                name = tmpname.lower().strip()
                val = map(lambda x: x.strip(), tmpval.split(','))
            else:
                name, val = headerline.lower(), None
            r['headers'][name] = val
        r['body'] = body
        return r



def mysendto(sock, data, dst):
    while data:
        bytes_sent = sock.sendto(data[:8192], dst)
        data = data[bytes_sent:]

def challengeResponse(auth, method, uri):
    hashlibsupported = True
    try:
        from hashlib import md5
    except ImportError:
        import md5 as md5sum
        md5 = md5sum.new
    import uuid
    username = auth["username"]
    realm = auth["realm"]
    passwd = auth["password"]
    nonce = auth["nonce"]
    opaque = auth["opaque"]
    algorithm = auth["algorithm"]
    cnonce = ""
    qop = None
    if auth["qop"] != None:
        qop = auth["qop"].split(',')[0]
    result = 'Digest username="%s",realm="%s",nonce="%s",uri="%s"' % (
        username, realm, nonce, uri)
    if algorithm == "md5-sess" or qop == "auth":
        cnonce = uuid.uuid4().get_hex()
        nonceCount = "%08d" % auth["noncecount"]
        result += ',cnonce="%s",nc=%s' % (cnonce, nonceCount)
    if algorithm is None or algorithm == "md5":
        ha1 = md5('%s:%s:%s' % (username, realm, passwd)).hexdigest()
        result += ',algorithm=MD5'
    elif auth["algorithm"] == "md5-sess":
        ha1 = md5(md5('%s:%s:%s' % (username, realm, passwd)
                      ).hexdigest() + ":" + nonce + ":" + cnonce).hexdigest()
        result += ',algorithm=MD5-sess'
    else:
        print("Unknown algorithm: %s" % auth["algorithm"])
    if qop is None or qop == "auth":
        ha2 = md5('%s:%s' % (method, uri)).hexdigest()
        result += ',qop=auth'
    if qop == "auth-int":
        print "auth-int is not supported"
    if qop == "auth":
        res = md5(ha1 + ":" + nonce + ":" + nonceCount + ":" +
                  cnonce + ":" + qop + ":" + ha2).hexdigest()
    else:
        res = md5('%s:%s:%s' % (ha1, nonce, ha2)).hexdigest()
    result += ',response="%s"' % res
    if opaque is not None and opaque != "":
        result += ',opaque="%s"' % opaque
    return result

def makeRequest(
    method, fromaddr, toaddr, dsthost, port, callid, srchost='',
    branchunique=None, cseq=1, auth=None, localtag=None, compact=False, contact='sip:123@1.1.1.1', accept='application/sdp', contentlength=None,
    localport=5060, extension=None, contenttype=None, body='',
        useragent='friendly-scanner', requesturi=None):
    """makeRequest builds up a SIP request
    method - OPTIONS / INVITE etc
    toaddr = to address
    dsthost = destination host
    port = destination port
    callid = callerid
    srchost = source host
    """
    import random
    if extension is None or method == 'REGISTER':
        uri = 'sip:%s' % dsthost
    else:
        uri = 'sip:%s@%s' % (extension, dsthost)
    if branchunique is None:
        branchunique = '%s' % random.getrandbits(32)
    headers = dict()
    finalheaders = dict()
    superheaders = dict()
    if method == 'ACK':
        localtag = None
    if compact:
        superheaders[
            'v'] = 'SIP/2.0/UDP %s:%s;branch=z9hG4bK-%s;rport' % (srchost, port, branchunique)
        headers['t'] = toaddr
        headers['f'] = fromaddr
        if localtag is not None:
            headers['f'] += ';tag=%s' % localtag
        headers['i'] = callid
        # if contact is not None:
        headers['m'] = contact
    else:
        superheaders[
            'Via'] = 'SIP/2.0/UDP %s:%s;branch=z9hG4bK-%s;rport' % (srchost, localport, branchunique)
        headers['Max-Forwards'] = 70
        headers['To'] = toaddr
        headers['From'] = fromaddr
        headers['User-Agent'] = useragent
        if localtag is not None:
            headers['From'] += ';tag=%s' % localtag
        headers['Call-ID'] = callid
        # if contact is not None:
        headers['Contact'] = contact
    headers['CSeq'] = '%s %s' % (cseq, method)
    headers['Max-Forwards'] = 70
    headers['Accept'] = accept
    if contentlength is None:
        headers['Content-Length'] = len(body)
    else:
        headers['Content-Length'] = contentlength
    if contenttype is None and len(body) > 0:
        contenttype = 'application/sdp'
    if contenttype is not None:
        headers['Content-Type'] = contenttype
    if auth is not None:
        response = challengeResponse(auth, method, uri)
        if auth['proxy']:
            finalheaders['Proxy-Authorization'] = response
        else:
            finalheaders['Authorization'] = response

    r = '%s %s SIP/2.0\r\n' % (method, uri)
    if requesturi is not None:
        r = '%s %s SIP/2.0\r\n' % (method, requesturi)
    for h in superheaders.iteritems():
        r += '%s: %s\r\n' % h
    for h in headers.iteritems():
        r += '%s: %s\r\n' % h
    for h in finalheaders.iteritems():
        r += '%s: %s\r\n' % h
    r += '\r\n'
    r += body
    return(r)

def createTag(data):
    from binascii import b2a_hex
    from random import getrandbits
    rnd = getrandbits(32)
    return b2a_hex(str(data) + '\x01' + str(rnd))

def getNonce(pkt):
    import re
    nonceRE = 'nonce="(.+?)"'
    _tmp = re.findall(nonceRE, pkt)
    if _tmp is not None:
        if len(_tmp) > 0:
            return(_tmp[0])
    return None

def getTag(buff):
    import re
    from binascii import a2b_hex
    tagRE = '(From|f): .*?\;\s*tag=([=+/\.:a-zA-Z0-9_]+)'
    _tmp = re.findall(tagRE, buff)
    if _tmp is not None:
        if len(_tmp) > 0:
            _tmp2 = _tmp[0][1]
            try:
                _tmp2 = a2b_hex(_tmp2)
            except TypeError:
                return
            if _tmp2.find('\x01') > 0:
                try:
                    c, rand = _tmp2.split('\x01')
                except ValueError:
                    c = 'svcrash detected'
            else:
                c = _tmp2
            return c

def getCredentials(buff):
    data = getTag(buff)
    if data is None:
        return
    userpass = data.split(':')
    if len(userpass) > 0:
        return(userpass)

def getRealm(pkt):
    import re
    nonceRE = 'realm="(.+?)"'
    _tmp = re.findall(nonceRE, pkt)
    if _tmp is not None:
        if len(_tmp) > 0:
            return(_tmp[0])
    return None

def getCID(pkt):
    import re
    cidRE = 'Call-ID: ([:a-zA-Z0-9]+)'
    _tmp = re.findall(cidRE, pkt, re.I)
    if _tmp is not None:
        if len(_tmp) > 0:
            return(_tmp[0])
    return None

def fingerPrint(request, src=None, dst=None):
    # work needs to be done here
    import re
    server = dict()
    if request.has_key('headers'):
        header = request['headers']
        if (src is not None) and (dst is not None):
            server['ip'] = src[0]
            server['srcport'] = src[1]
            if server['srcport'] == dst[1]:
                server['behindnat'] = False
            else:
                server['behindnat'] = True
        if header.has_key('user-agent'):
            server['name'] = header['user-agent']
            server['uatype'] = 'uac'
        if header.has_key('server'):
            server['name'] = header['server']
            server['uatype'] = 'uas'
        if header.has_key('contact'):
            m = re.match('<sip:(.*?)>', header['contact'][0])
            if m:
                server['contactip'] = m.group(1)
        if header.has_key('supported'):
            server['supported'] = header['supported']
        if header.has_key('accept-language'):
            server['accept-language'] = header['accept-language']
        if header.has_key('allow-events'):
            server['allow-events'] = header['allow-events']
        if header.has_key('allow'):
            server['allow'] = header['allow']
    return server

def fingerPrintPacket(buff, src=None):
    header = parseHeader(buff)
    if header is not None:
        return fingerPrint(header, src)

def printf(data):
    import sys
    n = len(data.splitlines())
    sys.stdout.write("\033[F"*n) # back 4 line
    sys.stdout.write("\033[K"*n) # clear last line
    print data

