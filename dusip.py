#!/usr/bin/env python
# dusip " dictionry attack to find sip users"


import socket
import time
import logging
import select
import random
from hlib import *

class TakeASip:

    def __init__(self, host='localhost', bindingip='', externalip=None, localport=5060, port=5060,
                 method='REGISTER', userFile=None, selecttime=0.05,
                 compact=False, socktimeout=10, initialcheck=True,
                 enableack=False, maxlastrecvtime=15, domain=None, printdebug=False,
                 ):
        self.log = logging.getLogger('TakeASip')
        self.maxlastrecvtime = maxlastrecvtime
        self.dbsyncs = False
        self.enableack = enableack
        self.resultauth = dict()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(socktimeout)
        self.bindingip = bindingip
        self.localport = localport
        self.originallocalport = localport
        self.rlist = [self.sock]
        self.wlist = list()
        self.xlist = list()
        self.challenges = list()
        self.realm = None
        self.uname = 'unknown'
        self.dsthost, self.dstport = host, int(port)
        self.domain = self.dsthost 
        if domain:
            self.domain = domain
        self.usernamegen = dictionaryattack(userFile)
        self.selecttime = selecttime
        self.compact = compact
        self.nomore = False
        self.BADUSER = None
        self.method = method.upper()
        if self.method == 'INVITE':
            self.log.warn('using an INVITE scan on an endpoint (i.e. SIP phone) may cause it to ring and wake up people in the middle of the night')
        self.initialcheck = initialcheck
        self.lastrecvtime = time.time()
        if externalip is None:
            self.log.debug("external ip was not set")
            if (self.bindingip != '0.0.0.0') and (len(self.bindingip) > 0):
                self.log.debug("but bindingip was set! we'll set it to the binding ip")
                self.externalip = self.bindingip
            else:
                try:
                    self.log.info("trying to get self ip .. might take a while")
                    self.externalip = socket.gethostbyname(
                        socket.gethostname())
                except socket.error:
                    self.externalip = '127.0.0.1'
        else:
            self.log.debug("external ip was set")
            self.externalip = externalip
        self.printdebug = printdebug
        # this req types
        self.proxyauthreq = 0
        self.authreq = 0
        self.invalidpass = 0
        self.okey = 0
        self.trying = 0
        self.ringing = 0
        self.notallowed = 0
        self.unavailable = 0
        self.declined = 0
        self.inexistent = 0
        self.busyhere = 0
        self.notfound = 0
        self.weird = 0
        self.unknown = 0
        self.transaction = 0
        self.intrnalerror = 0
#   SIP response codes, also mapped to ISDN Q.931 disconnect causes.

    PROXYAUTHREQ = 'SIP/2.0 407 '  #reqauth
    AUTHREQ = 'SIP/2.0 401 '       #reqauth
    OKEY = 'SIP/2.0 200 '          #noauth
    NOTFOUND = 'SIP/2.0 404 '
    INVALIDPASS = 'SIP/2.0 403 '   #reqauth
    TRYING = 'SIP/2.0 100 '
    RINGING = 'SIP/2.0 180 '
    NOTALLOWED = 'SIP/2.0 405 '
    UNAVAILABLE = 'SIP/2.0 480 '
    DECLINED = 'SIP/2.0 603 '
    INEXISTENTTRANSACTION = 'SIP/2.0 481'
    BUSYHERE  = 'SIP/2.0 486' 
    INERNALERROR = 'SIP/2.0 500'  # in (FPBX-14.0.3.13) you get this if user not True

    # Mapped to ISDN Q.931 codes - 88 (Incompatible destination), 95 (Invalid message), 111 (Protocol error)
    # If we get something like this, then most probably the remote device SIP stack has troubles with
    # understanding / parsing our messages (a.k.a. interopability problems).
    BADREQUEST = 'SIP/2.0 400 '

    # Mapped to ISDN Q.931 codes - 34 (No circuit available), 38 (Network out of order), 41 (Temporary failure),
    # 42 (Switching equipment congestion), 47 (Resource unavailable)
    # Should be handled in the very same way as SIP response code 404 - the prefix is not correct and we should
    # try with the next one.
    SERVICEUN = 'SIP/2.0 503 '

    def createRequest(self, m, username=None, auth=None, cid=None, cseq=1, fromaddr=None, toaddr=None, contact=None):
        from base64 import b64encode

        if cid is None:
            cid = '%s' % str(random.getrandbits(32))
        branchunique = '%s' % random.getrandbits(32)
        localtag = createTag(username)
        if not contact:
            contact = 'sip:%s@%s' % (username, self.domain)
        if not fromaddr:
            fromaddr = '"%s"<sip:%s@%s>' % (username, username, self.domain)
        if not toaddr:
            toaddr = '"%s"<sip:%s@%s>' % (username, username, self.domain)
        request = makeRequest(
            m,
            fromaddr,
            toaddr,
            self.domain,
            self.dstport,
            cid,
            self.externalip,
            branchunique,
            cseq,
            auth,
            localtag,
            self.compact,
            contact=contact,
            localport=self.localport,
            extension=username
        )

        return request

    def showResponce(self):
        i = '		'
        rebot =  'ip [{}]     port[{}]      sip-system [{}] \r\n'.format(self.dsthost, self.dstport, self.uname)
        rebot += '============================================================================\r\n'
        rebot += 'AUTHREQ(401):{0}{3} PROXYAUTHREQ(407):{1}{3} INVALIDPASS(403):{2}\r\n'.format(self.authreq, self.proxyauthreq, self.invalidpass, i)
        rebot += 'OKEY   (200):{0}{3} NOTFOUND    (404):{1}{3} TRYING     (100):{2}\r\n'.format(self.okey, self.notfound, self.trying, i)
        rebot += 'BUSY   (486):{0}{3} UNAVAILABLE (480):{1}{3} RINGING    (180):{2}\r\n'.format(self.busyhere, self.unavailable, self.invalidpass, i)
        rebot += 'DECLIND(603):{0}{3} INTERNALL   (500):{1}{3} TRANSACTION(481):{2}\r\n'.format(self.declined, self.intrnalerror, self.transaction, i)
        rebot += 'Weird  (???):{0}{2} Unknown     (!!!):{1}{2}'.format(self.weird, self.unknown, i)
        printf(rebot)


    def getResponse(self):
        # we got stuff to read off the socket
        buff, srcaddr = self.sock.recvfrom(8192)
        if self.printdebug:
            print buff.splitlines()[0]
        else:
            self.showResponce()
        try:
            extension = getTag(buff)
        except TypeError:
            self.log.error('could not decode to tag')
            extension = None
        if extension is None:
            self.nomore = True
            return
        try:
            firstline = buff.splitlines()[0]
        except (ValueError, IndexError, AttributeError):
            self.log.error("could not get the 1st line")
            return
        if self.enableack:
            # send an ack to any responses which match
            _tmp = parseHeader(buff)
            if not (_tmp and _tmp.has_key('code')):
                return
            if 699 > _tmp['code'] >= 200:
                self.log.debug('will try to send an ACK response')
                if not _tmp.has_key('headers'):
                    self.log.debug('no headers?')
                    return
                if not _tmp['headers'].has_key('from'):
                    self.log.debug('no from?')
                    return
                if not _tmp['headers'].has_key('cseq'):
                    self.log.debug('no cseq')
                    return
                if not _tmp['headers'].has_key('call-id'):
                    self.log.debug('no caller id')
                    return
                try:
                    username = getTag(buff)
                except IndexError:
                    self.log.warn('could not parse the from address %s' % _tmp[
                                  'headers']['from'])
                    username = 'XXX'
                cseq = _tmp['headers']['cseq'][0]
                cseqmethod = cseq.split()[1]
                if 'INVITE' == cseqmethod:
                    cid = _tmp['headers']['call-id'][0]
                    fromaddr = _tmp['headers']['from'][0]
                    toaddr = _tmp['headers']['to'][0]
                    ackreq = self.createRequest('ACK',
                                                cid=cid,
                                                cseq=cseq.replace(
                                                    cseqmethod, ''),
                                                fromaddr=fromaddr,
                                                toaddr=toaddr,
                                                )
                    mysendto(self.sock, ackreq, (self.dsthost, self.dstport))
                    if _tmp['code'] == 200:
                        byemsg = self.createRequest('BYE',
                                                    cid=cid,
                                                    cseq='2',
                                                    fromaddr=fromaddr,
                                                    toaddr=toaddr,
                                                    )
                        self.log.debug(
                            'sending a BYE to the 200 OK for the INVITE')
                        mysendto(self.sock, byemsg,
                                 (self.dsthost, self.dstport))
#        print firstline 
#        print self.BADUSER
        if firstline != self.BADUSER:
            if buff.startswith(self.PROXYAUTHREQ) :
               self.proxyauthreq += 1
               if self.realm is None:
                   self.realm = getRealm(buff)
               self.log.info("extension '%s' exists - requires authentication" % extension)
               self.resultauth[extension] = 'reqauth'

            elif buff.startswith(self.INVALIDPASS) :
                self.invalidpass += 1
                if self.realm is None:
                    self.realm = getRealm(buff)
                self.log.info("extension '%s' exists - requires authentication" % extension)
                self.resultauth[extension] = 'reqauth'

            elif buff.startswith(self.AUTHREQ):
                self.authreq += 1 

                if self.realm is None:
                    self.realm = getRealm(buff)
                self.log.info("extension '%s' exists - requires authentication" % extension)
                self.resultauth[extension] = 'reqauth'
            elif buff.startswith(self.TRYING):
                self.trying += 1
            elif buff.startswith(self.RINGING):
                self.ringing += 1
            elif buff.startswith(self.OKEY):
                self.okey += 1
                self.log.info("extension '%s' exists - authentication not required" % extension)
#                self.resultauth[extension] = 'noauth'
            elif buff.startswith(self.BUSYHERE):
                self.busyhere += 1
            else:
                self.weird += 1
                self.log.warn("extension '%s' probably exists but the response is unexpected" % extension)
                self.log.debug("response: %s" % firstline)
#                self.resultauth[extension] = 'weird'

        
        elif buff.startswith(self.NOTFOUND):
            self.notfound += 1
            self.log.debug("User '%s' not found" % extension)
        elif buff.startswith(self.INEXISTENTTRANSACTION):
            self.inexistent += 1
        # Prefix not found, lets go to the next one. Should we add a warning
        # here???
        elif buff.startswith(self.INERNALERROR):
             self.intrnalerror += 1
        elif buff.startswith(self.SERVICEUN):
             self.unknown += 1
        elif buff.startswith(self.TRYING):
             self.unknown += 1
        elif buff.startswith(self.RINGING):
             self.unknown += 1
        elif buff.startswith(self.OKEY):
             self.unknown += 1
        elif buff.startswith(self.DECLINED):
             self.unknown += 1
        elif buff.startswith(self.PROXYAUTHREQ):
             self.unknown += 1
        elif buff.startswith(self.NOTALLOWED):
            self.nomore = True
            self.log.warn("method not allowed")
            return
        elif buff.startswith(self.BADREQUEST):
            self.log.error("Protocol / interopability error! The remote side most probably has problems with parsing your SIP messages!")
            self.nomore = True
            return
        else:
            self.log.warn("We got an unknown response")
            self.log.error("Response: %s" % `buff`)
            self.log.debug("1st line: %s" % `firstline`)
            self.log.debug("Bad user: %s" % `self.BADUSER`)
            self.unknown += 1
#            self.nomore = True


#   SIP response codes, also mapped to ISDN Q.931 disconnect causes.

    PROXYAUTHREQ = 'SIP/2.0 407 '  #reqauth
    AUTHREQ = 'SIP/2.0 401 '       #reqauth
    OKEY = 'SIP/2.0 200 '          #noauth
    NOTFOUND = 'SIP/2.0 404 '
    INVALIDPASS = 'SIP/2.0 403 '   #reqauth
    TRYING = 'SIP/2.0 100 '
    RINGING = 'SIP/2.0 180 '
    NOTALLOWED = 'SIP/2.0 405 '
    UNAVAILABLE = 'SIP/2.0 480 '
    DECLINED = 'SIP/2.0 603 '
    INEXISTENTTRANSACTION = 'SIP/2.0 481'
    BUSYHERE = 'SIP/2.0 486'

    def start(self):
        if self.bindingip == '':
            bindingip = 'any'
        else:
            bindingip = self.bindingip
        self.log.debug("binding to %s:%s" % (bindingip, self.localport))
        while 1:
            if self.localport > 65535:
                self.log.critical("Could not bind to any port")
                return
            try:
                self.sock.bind((self.bindingip, self.localport))
                break
            except socket.error:
                self.log.debug("could not bind to %s" % self.localport)
                self.localport += 1
        if self.originallocalport != self.localport:
            self.log.warn("could not bind to %s:%s - some process might already be listening on this port. Listening on port %s instead" %
                          (self.bindingip, self.originallocalport, self.localport))
            self.log.info("Make use of the -P option to specify a port to bind to yourself")

        # perform a test 1st .. we want to see if we get a 404
        # some other error for unknown users
        self.nextuser = random.getrandbits(32)
        data = self.createRequest(self.method, self.nextuser)
        try:
            mysendto(self.sock, data, (self.dsthost, self.dstport))
            # self.sock.sendto(data,(self.dsthost,self.dstport))
        except socket.error, err:
            self.log.error("socket error: %s" % err)
            return
        # first we identify the assumed reply for an unknown extension
        gotbadresponse = False

        try:
            while 1:
                try:
                    buff, srcaddr = self.sock.recvfrom(8192)
                    if self.printdebug:
                        print buff.splitlines()[0]
                    else:
                        self.showResponce()
                except socket.error, err:
                    self.log.error("socket error: %s" % err)
                    return
                if buff.startswith(self.TRYING) or buff.startswith(self.RINGING) or buff.startswith(self.UNAVAILABLE):
                    gotbadresponse = True
                elif buff.startswith(self.PROXYAUTHREQ) or buff.startswith(self.INVALIDPASS) or buff.startswith(self.AUTHREQ) and self.initialcheck:
                    self.log.error("SIP server replied with an authentication request for an unknown extension. Set --force to force a scan.")
                    return
                else:
                    self.BADUSER = buff.splitlines()[0]
                    self.log.debug("Bad user = %s" % self.BADUSER)
                    gotbadresponse = False
                    break
        except socket.timeout:
            if gotbadresponse:
                self.log.error("The response we got was not good: %s" % `buff`)
            else:
                self.log.error("No server response - are you sure that this PBX is listening? run svmap against it to find out")
            return
        except (AttributeError, ValueError, IndexError):
            self.log.error("bad response .. bailing out")
            return
        except socket.error, err:
            self.log.error("socket error: %s" % err)
            return
        if self.BADUSER.startswith(self.AUTHREQ):
            self.log.warn("Bad user = %s - svwar will probably not work!" % self.AUTHREQ)
        # let the fun commence
        self.log.info('Ok SIP device found')
        try:
           self.uname = fingerPrintPacket(buff)['name'][0]
        except :
           pass

        while 1:
            if self.nomore:
                while 1:
                    try:
                        self.getResponse()
                    except socket.timeout:
                        return
            r, w, e = select.select(
                self.rlist,
                self.wlist,
                self.xlist,
                self.selecttime
            )
            if r:
                # we got stuff to read off the socket
                self.getResponse()
                self.lastrecvtime = time.time()
            else:
                # check if its been a while since we had a response to prevent
                # flooding - otherwise stop
                timediff = time.time() - self.lastrecvtime
                if timediff > self.maxlastrecvtime:
                    self.nomore = True
                    self.log.warn('It has been %s seconds since we last received a response - stopping' % timediff)
                    continue
                # no stuff to read .. its our turn to send back something
                try:
                    self.nextuser = self.usernamegen.pop()#.next()
                except IndexError: 
                    self.nomore = True
                except StopIteration:
                    self.nomore = True
                    continue
                except TypeError:
                    self.nomore = True

                    self.log.exception('Bad format string')
                data = self.createRequest(self.method, self.nextuser)
                try:
                    self.log.debug("sending request for %s" % self.nextuser)
                    mysendto(self.sock, data, (self.dsthost, self.dstport))

                except socket.error, err:
                    self.log.error("socket error: %s" % err)
                    break

    def __del__(self):
       try:
          self.sock.shutdown(socket.SHUT_RDWR)
          self.sock.close()
       except:
          pass
       lenres = len(self.resultauth)
       result = open('ipuser.txt','a+')
       loot = self.dsthost
       if lenres > 0:
            self.log.info("we have %s extensions" % lenres)
            for k in self.resultauth.keys():
                loot +=','+k
            result.write(loot+'\n')
       else:
            self.log.warn("found nothing")
       result.close()





from optparse import OptionParser
from sys import exit
usage = "examples:\r\n"
usage += "dusip.py -d dictionary.txt 10.0.0.2\r\n"
usage += "dusip.py -d dictionary.txt -i iplist.txt -m INVITE --debug\r\n"

parser = OptionParser(usage)

parser.add_option("-d", "--dictionary", dest="dictionary", type="string",
                      help="specify a dictionary file with possible extension names",
                      metavar="DICTIONARY")
parser.add_option("-i", "--iplist", dest="iplist", type="string",
                      help="specify a dictionary file with possible ips",
                      metavar="DICTIONARY")
parser.add_option("-m", "--method", dest="method", type="string",
                      help="specify a request method. The default is REGISTER. Other possible methods are OPTIONS and INVITE",
                      default="REGISTER",metavar="OPTIONS")
parser.add_option('--force', dest="force", action="store_true",default=False,
                      help="Force scan, ignoring initial sanity checks.")
parser.add_option('--maximumtime', action='store', dest='maximumtime', type="int",default=10,
                      help="Maximum time in seconds to keep sending requests without receiving a response back")
parser.add_option('--domain', dest="domain",
                      help="force a specific domain name for the SIP message, eg. -d example.org")
parser.add_option("--debug", dest="printdebug",
                      help="Print SIP messages received",default=False, action="store_true")
parser.add_option("--port", dest="port",
                      help="port SIP target to send",default=5060, type='int')

(options, args) = parser.parse_args()



def sipUserScan():
    logging.basicConfig(filename='logging.txt',writemod='w',level=20)
    logging.debug('started logging')
    if options.force:
        initialcheck = False
    else:
        initialcheck = True
    if len(args) == 1:
        hosts = list()
        hosts.append(args[0])
    else:
       try:# that for hosts
          hosts = dictionaryattack(options.iplist)
       except IOError, err:
          logging.error("could not open %s" % options.dictionary)
          exit(1)

    enableack = False
    if options.method.upper() == 'INVITE':
        enableack = True

    for host in hosts :
       sipvicious = TakeASip(
           host,
           port=options.port,
           method=options.method,
           userFile=options.dictionary,
           initialcheck=initialcheck,
           enableack=enableack,
           maxlastrecvtime=options.maximumtime,
           domain=options.domain,
           printdebug=options.printdebug)
       try:
          sipvicious.start()
       except KeyboardInterrupt:
          logging.warn('caught your control^c - quiting')
       except Exception, err:
          logging.exception("Exception")




if len(args) == 1 or options.iplist and options.dictionary :
    sipUserScan()
else:
   print usage
