#!/usr/bin/env python

#
# UCCid, the UCC OpenID server.
#

# Standard libraries and path append.
import os, sys, shelve, re, os.path
from time import time, strftime, gmtime
import threading

# Need this for web.py, flup, openid. web.py has been customised a bit. -- sj26
sys.path[0:0] = ["/home/wheel/sj26/lib/python/"]

# OpenID imports... I know it's wacky but it makes the
# later code cleaner.
from openid.server.server import ProtocolError, Server as OpenIDServer
from openid.store.filestore import FileOpenIDStore

# Web.py and flup!
import web, cgi
import flup, flup.server.fcgi, flup.middleware.session
from web.cheetah import render
from cgi import escape

from json import JsonWriter

import ldap

# TODO:
#  * Multiple ID sources (tartarus? cyllene?)
#  * Pretty up templates 
#  * Look at security of variable passing to templates and whether websafe
#    or htmlquote should be used more.

# Some definitions.
base_dir = "/services/http-openid/"
base_url = "https://secure.ucc.asn.au/openid/"
base_identity = "http://%(user)s.ucc.asn.au/"
username_re = re.compile("http://([a-zA-Z0-9_-]+).ucc.asn.au/")

# Had to hack up web.py a bit to make cheetah templating work how I wanted.
# Should probably copy the cheetah.py file out of web.py and keep our own
# version. -- sj26
web.cheetah.base_dir = base_dir

# Url design and delegation, fairly boring.
# TODO: As these are all boring URLs would it be worth changing the default
# web.py handler to a pure plaintext selector? -- sj26
# NOTE: /www is because of Apache rewriting h4x.
urls = (
  "/www/(login)", "CheckID",
  "/www/(approve)", "CheckID",
  "/www/account", "Account",
  "/www/about", "About",
  "/www/logout", "Logout",
  ".*", "OpenID")

# Initialise the library.
store = FileOpenIDStore(base_dir + "store/openid/")
server = OpenIDServer(store)

# Make debugging fun!
web.webapi.internalerror = web.debugerror
web.debug = open(base_dir + 'debug.log', 'a')

class TrustDB:
  """
  Holds a list of trust roots their approval states for a specified identity.

  TODO: This probably needs moving to an SQL database. Postgres? -- sj26
  """

  # Approved states6
  APPROVED_ONCE = 1
  APPROVED_ALWAYS = 2
  approved_map = dict(once=APPROVED_ONCE, always=APPROVED_ALWAYS)

  def __init__(self, user):
    self.user = user
    self.shelf = shelve.open(self.trust_file(), flag='c')

  def __getitem__(self, trust_root):
    return self.shelf.get(trust_root, False)
  
  def __setitem__(self, trust_root, trust_approval):
    trust_approval = TrustDB.approved_map.get(trust_approval, trust_approval)
    if trust_approval not in TrustDB.approved_map.values():
      raise ValueError("Invalid trust approval.")
    self.shelf[trust_root] = trust_approval

  def __delitem__(self, trust_root):
    del self.shelf[trust_root]

  def __iter__(self):
    return self.shelf.__iter__()

  def __repr__(self):
    return "<TrustDB %s>" % repr(self.shelf)

  def items(self):
    return self.shelf.items()

  def get(self, *a, **kw):
    return self.shelf.get(*a, **kw)
  
  def trust_file(self):
    """ Returns the name of the trust file for the current user. """
    return base_dir + "store/trust/" + self.user

def is_trusted(trust_root, by=None):
  """
  Asserts that a user trusts this trust_root. Removes the trust entry if trust
  is TrustDB.APPROVED_ONCE .
  """
  if by == None: by = web.session.user
  trust_db = TrustDB(by)
  approval = trust_db[trust_root]
  if approval == TrustDB.APPROVED_ONCE:
    del trust_db[trust_root]
  return approval

def is_logged_in(username=None):
  """
  Asserts that the specified user is currently logged in.
  """

  if web.session.get("user", None) == None:
    return False

  if username != None:
    if username != web.session.user:
      return False

  if web.session.get("ip", web.ctx.ip) != web.ctx.ip:
    return False

  return True

def logged_in(f):
  """ Decorator which will redirect to login page if not logged in. """
  def internal(*a, **kw):
    if not is_logged_in():
      return web.seeother("login")
    f(*a, **kw)
  return internal

def verify_session_ip():
  """ Stop session hijacks. """
  web.ctx.ip = web.ctx.env.get("HTTP_X_FORWARDED_FOR", web.ctx.ip)
  if web.session.get('ip', None) != None and web.session.ip != web.ctx.ip:
    web.session.user = None
    web.session.ip = None
    web.ctx.status = "403"
    web.ctx.output = "Session is invalid."
    return False
web._loadhooks['verify_session_ip'] = verify_session_ip

def username_from_identity(identity):
  """ Extract the username from an identity. """
  match = username_re.match(identity)
  if match != None:
    return match.groups()[0]
  return None

def get_request(query=None, request_key=None):
  """ Get the current OpenID request. Returns None on failure. """
  query = web.input()

  # Grab from session if possible
  if request_key == None and 'request' in query and query.request not in ['user', 'ip']:
    request_key = query.request
  if request_key != None:
    request = web.session.get(request_key, None)
    if request != None:
      return request

  # Otherwise look for the request in query parameters
  try:
    return server.decodeRequest(query)
  except ProtocolError, why:
    pass

  # Catch all
  return None

def valid_request(request):
  """ Make sure the request is valid and legal. """
  # Is the return_to address within the trust_root?
  if request != None and not request.trustRootValid():
    # TODO: should probably explain this to the user
    web.seeother(request.getCancelURL())
    return False
  return True

def request_identity(request):
  # Extract username and identity from request if possible.
  if request != None:
    return request.identity, username_from_identity(request.identity)
  return None, None

class CheckID:
  def GET(self, mode, failed=False, failed_username=None, request_key=None):
    global base_identity

    if request_key == None: request_key = web.input().get('request', None)
    request = get_request(request_key=request_key)
    if request != None: assert valid_request(request)

    identity, username = request_identity(request)
    default_username = None
    if username == None and failed_username != None:
      default_username = failed_username
      identity = base_identity % dict(user=default_username)

    # Redirect if neccessary
    if mode == "login" and is_logged_in(username):
      if request != None:
        return web.seeother("approve?request=%s" % request_key)
      else:
        return web.seeother("account")
    elif mode == "approve" and not is_logged_in(username):
      return web.seeother("login?request=%s" % request_key)
    elif mode == "approve" and is_trusted(request.trust_root):
      return web.seeother(base_url + "?request=" + request_key)

    # For the template
    trust_root = None
    if request != None: trust_root = request.trust_root
    if username == None: username = ""
    terms = {'username': username, 'identity': identity, 'failed': failed,
      'base_identity': base_identity, 'trust_root': trust_root,
      'default_username': default_username, 'request': request, 
      'request_key': request_key}

    if mode == "login":
      terms.update({'title': "Login", 'mode': "login",
        'submit_name': "Login", 'cancel_name': "Cancel"})
    else:
      terms.update({'title': "Identification Approval", 'mode': "approve",
        'submit_name': "Approve", 'cancel_name': "Cancel"})

    return render("checkid.html", terms=terms)

  def POST(self, mode):
    query = web.input()
    request_key = query.get('request', '')

    request = get_request()
    assert valid_request(request)

    if "cancel" in query:
      if request != None:
        return web.seeother(request.getCancelURL())
      else:
        return web.seeother("account")
    # Beyond here I'm assuming submit (hitting enter won't set the query parameter)
    elif mode == "login":
      query = web.input("username", "password")
      web.session.remember = query.get('remember', False)
      # TODO: REALLY needs some sort of validation/filtering of input details.
      try:
        dn = "uid=%s,ou=People,dc=ucc,dc=gu,dc=uwa,dc=edu,dc=au" % query.username
        assert ldap.open("localhost").simple_bind_s(dn, query.password)[0] == 97
      except ldap.INVALID_CREDENTIALS:
        return self.GET("login", failed=True, failed_username=query.username)

      web.session.user = query.username
      web.session.ip = web.ctx.ip

      # If we're remembering this session write a cookie to do so.
      if web.session.remember == 'forever':
        rid = flup.middleware.session.Session.generateIdentifier()
        open(base_dir + 'store/remember/' + web.session.user, 'w').write(rid)
        # Set a remember cookie expiring in 2030
        web.setcookie('uccid_remember', web.session.user + ':' + rid, 
          expires=strftime("%a, %d-%b-%Y %H:%M:%S GMT", gmtime(60 * (365.25*60*60*24))),
          domain='secure.ucc.asn.au')

      if request != None:
        if is_trusted(request.trust_root):
          return web.seeother(base_url + "?request=" + request_key)
        else:
          return web.seeother("approve?request=" + request_key)
      else:
        return web.seeother("account")
    elif mode == "approve":
      if request != None:
        approval = TrustDB.APPROVED_ONCE
        if query.get("always", False):
          approval = TrustDB.APPROVED_ALWAYS
        trustdb = TrustDB(web.session.user)
        trustdb[request.trust_root] = approval
        return web.seeother(base_url + "?request=" + request_key)
    else:
      raise Exception("Strange %s %r." % (mode, web.ctx.query))

  def request_fields(self, request):
    response = ""
    for name, value in web.input().items():
      if name.startswith("openid."):
        response += """<input type="hidden" name="%s" value="%s" />""" % (escape(name), escape(value))
    return response

class Account:
  """
  Shows account information
  """
  @logged_in
  def GET(self, success=None, notice=None):
    query = web.input()
    success, notice = False, None
    self.trust_db = TrustDB(web.session.user)

    if 'untrust' in query:
      if self.trust_db.get(query.untrust, None) != None:
        del self.trust_db[query.untrust]
        success = True
        notice = "The site %s is not longer trusted." % query.untrust
      else:
        notice = "You do not currently trust that site."

    if 'json' in query:
      json = dict(success=success)
      if notice != None:
        json['notice'] = notice
      print JsonWriter.write(json)
      return

    sites = [site for site, approval in self.trust_db.items() if approval == TrustDB.APPROVED_ALWAYS]
    print render("account.html", terms=dict(
      success=success, notice=notice, sites=sites, user=web.session.user, ip=web.session.ip))

class Logout:
  def GET(self):
    web.session.invalidate()
    return web.seeother(base_url)
  POST = GET

class OpenID:
  """
  Handles the server-to-server communication of openid.
  
  Will redirect the user to an appropriate browser page if neccessary.
  """
  def GET(self):
    # try and decode the request, redirect if not present completely, or raise a 400 Bad Request
    request = get_request()
    if request == None:
      query = web.input()
      if 'openid.mode' in query:
        try:
          request = server.decodeRequest(query)
        except ProtocolError, why:
          web.badrequest()
      else:
        return web.seeother("about")

    print >>web.debug, "OpenID request (%s):" % request.mode, request

    # We handle login requests, but nothing else. Hooray python-openid!
    if request.mode in ["checkid_immediate", "checkid_setup"]:
      # Get username from requested identity, if possible.
      username = username_re.match(request.identity)
      if username != None:
        username = username.groups()[0]

      answer, mode = False, None
      
      # If we're already logged in and we trust the site, bounce straight back.
      if is_logged_in(username) and is_trusted(request.trust_root):
        answer = True
        # Now we've got our answer, if we're not remembering the session,
        # destroy it.
        if web.session.get('remember', 'never') not in ('always', 'session'):
          web.session.invalidate()
      # If we're logged in the user needs to be directed to the approval page.
      elif is_logged_in(username):
        answer = False
        mode = "approve"
      # Otherwise the user needs to be directed to the login page.
      else:
        answer = False
        mode = "login"

      # checkid_setup lets us do out login/approve process so we go to the
      # appropriate page
      if request.mode == "checkid_setup" and not answer:
        print >>web.debug, "Mode is %s, redirecting to %s." % (request.mode, mode)
        # TODO: use random identifier
        request_key = web.session.generateIdentifier()
        web.session[request_key] = request
        return CheckID().GET(mode, request_key=request_key)

      # checkid_immediate is the server asking us to check the id straigh away
      # and not to show any pages of our rown.
      else:
        if not answer:
          response = request.answer(answer, base_url + mode + web.ctx.query)
        else:
          response = request.answer(answer)
    
    # It's python-openid's job.
    else:
      response = server.handleRequest(request)

    # Turn the response into an HTTP message
    response = server.encodeResponse(response)

    # Spit out the response in web.py form
    status_dict = {302: "Redirect", 200: "Found"}
    web.ctx.status = str(response.code) + " " + status_dict[response.code]
    for header, value in response.headers.items():
      web.header(header, value)
    print response.body

  # Same deal for both methods.
  POST = GET

class About:
  def GET(self):
    render("index.html", terms=dict(user=web.session.user))

def cleanup_sessions():
  """ Cleans up sessions every 5 minutes. """
  web.env['com.saddi.service.session']._store.periodic()
  threading.Timer(300.0, cleanup_sessions)

if __name__ == "__main__":
  cookieAttributes = {'domain': 'secure.ucc.asn.au', 'path': '/openid/',
    'secure': 'secure'}
  session_mw = web.sessions(web.DiskSessionStore, \
    storeDir=base_dir+"store/session/", defaults={"user": None, "ip": None},
    cookieAttributes=cookieAttributes)
  threading.Timer(300.0, cleanup_sessions)
  sys.argv.append("fastcgi")
  web.run(urls, locals(), session_mw)

