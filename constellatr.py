import cgi
import keys
import os
import re
import uuid

from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext.webapp import template

import oauth2 as oauth

class RequestToken(db.Model):
    created = db.DateTimeProperty(auto_now_add=True)
    oauth_request_token = db.StringProperty(required=True)
    oauth_request_token_secret = db.StringProperty(required=True)

class AccessToken(db.Model):
    created = db.DateTimeProperty(auto_now_add=True)
    oauth_access_token = db.StringProperty(required=True)
    oauth_access_token_secret = db.StringProperty(required=True)
    rss_token = db.StringProperty(required=True)

consumer = oauth.Consumer(keys.consumer_key, keys.consumer_secret)

class Index(webapp.RequestHandler):
    def get(self):
        args = { }
        path = os.path.join(os.path.dirname(__file__), 'index.html')
        self.response.out.write(template.render(path, args))

request_token_url = 'https://api.twitter.com/oauth/request_token'
authorize_url = 'https://api.twitter.com/oauth/authorize'
access_token_url = 'https://api.twitter.com/oauth/access_token'
favorites_url = 'https://api.twitter.com/1/favorites.rss'

class Auth(webapp.RequestHandler):
    def get(self):
        client = oauth.Client(consumer)
        resp, content = client.request(request_token_url, method='POST')
        if resp['status'] != '200':
            raise Exception("Invalid response %s : %s." % (resp['status'], content))
        args = dict(cgi.parse_qsl(content)) # parse_qs returns a dict but vals are lists
        request_token = RequestToken(oauth_request_token = args['oauth_token'],
                                     oauth_request_token_secret = args['oauth_token_secret'])
        request_token.put()
        self.redirect(authorize_url + '?oauth_token=' + request_token.oauth_request_token)

class Callback(webapp.RequestHandler):
    def get(self):
        oauth_token = self.request.get('oauth_token')
        oauth_verifier = self.request.get('oauth_verifier')
        request_token = RequestToken.all().filter('oauth_request_token =', oauth_token).get()
        token = oauth.Token(request_token.oauth_request_token, request_token.oauth_request_token_secret)
        token.set_verifier(oauth_verifier)
        client = oauth.Client(consumer, token)
        resp, content = client.request(access_token_url, method='POST')
        if resp['status'] != '200':
            raise Exception("Invalid response %s : %s." % (resp['status'], content))
        args = dict(cgi.parse_qsl(content)) # parse_qs returns a dict but vals are lists
        access_token = AccessToken(oauth_access_token = args['oauth_token'],
                                   oauth_access_token_secret = args['oauth_token_secret'],
                                   rss_token = uuid.uuid4().hex)
        access_token.put()
        link = 'http://constellatr.appspot.com/rss/%s' % access_token.rss_token
        args = { 'link' : link }
        path = os.path.join(os.path.dirname(__file__), 'link.html')
        self.response.out.write(template.render(path, args))

class RSS(webapp.RequestHandler):
    def get(self, rss_token):
        access_token = AccessToken.all().filter('rss_token =', rss_token).get()
        token = oauth.Token(access_token.oauth_access_token, access_token.oauth_access_token_secret)
        client = oauth.Client(consumer, token)
        resp, content = client.request(favorites_url, method='GET')
        if resp['status'] != '200':
            raise Exception("Invalid response %s : %s." % (resp['status'], content))
        self.response.headers["Content-Type"] = "application/rss+xml"
        self.response.out.write(content)

handlers = [
    ('/', Index),
    ('/auth', Auth),
    ('/oauth/callback', Callback),
    (r'/rss/(.*)', RSS)
]

application = webapp.WSGIApplication(handlers, debug=True)

def main():
    run_wsgi_app(application)

if __name__ == "__main__":
    main()
