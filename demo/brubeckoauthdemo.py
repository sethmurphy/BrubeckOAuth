#!/usr/bin/env python
import sys
import logging
import httplib
import os
import json
import datetime
import time
import random
from urllib import unquote, quote

from brubeck.auth import authenticated
from brubeck.request_handling import Brubeck, JSONMessageHandler, cookie_encode, cookie_decode
from brubeck.templating import load_jinja2_env, Jinja2Rendering
from dictshield import fields
from dictshield.document import Document, EmbeddedDocument
from dictshield.fields import ShieldException
from gevent import Greenlet
from gevent.event import Event

from brubeck.auth import web_authenticated, UserHandlingMixin
from brubeckoauth.handlers import OAuthMixin
from brubeck.queryset import DictQueryset

##
## This will be in Brubeck core soon
##
def lazyprop(method):
    """A nifty wrapper to only load properties when accessed
    uses the lazyProperty pattern from: 
    http://j2labs.tumblr.com/post/17669120847/lazy-properties-a-nifty-decorator
    inspired by  a stack overflow question:
    http://stackoverflow.com/questions/3012421/python-lazy-property-decorator
    This is to replace initializing common variable from cookies, 
    query string, etc .. that would be in the prepare() method.
    THIS SHOULD BE IN BRUBECK CORE
    """
    attr_name = '_' + method.__name__
    @property
    def _lazyprop(self):
        if not hasattr(self, attr_name):
            attr = method(self)
            setattr(self, attr_name, method(self))
        return getattr(self, attr_name)
    return _lazyprop    


##
## demo oauth handler application
##

# Our oauth settings
# just twitter for now
# Yes, this is real info.
oauth = {
    "PROVIDERS": {
        "twitter": {
            "PROVIDER_NAME": "twitter",
            "PROVIDER_TAG": "tw",
            "OAUTH_VERSION": "1.0a",
            "CONSUMER_KEY": "5cpzeo2L38tZx8ItIWzPA",
            "CONSUMER_SECRET": "34dPZ0xg9jjRoG8mk18q5muyIgxdZm050LToGqc8",
            "REQUEST_TOKEN_URL": "https://api.twitter.com/oauth/request_token",
            "REQUEST_TOKEN_URL_HOST": "https://api.twitter.com",
            "REQUEST_TOKEN_URL_PATH": "/oauth/request_token",
            "AUTHORIZE_URL": "https://api.twitter.com/oauth/authorize",
            "ACCESS_TOKEN_URL": "https://api.twitter.com/oauth/access_token",
            "CALLBACK_URL": "http://brubeckoauth.sethmurphy.com/oauth/twitter/callback",
            "USER_INFO": [  
                ["https://api.twitter.com/1/account/verify_credentials.json", 
                    [
                        ["username", ["screen_name"]], 
                        ["email", ["screen_name"]], 
                        ["oauth_uid", ["id"]],
                        ["thumbnailLarge", ["profile_image_url"]],
                    ],
                ],
            ],
            "ALIASES": [  
                ["fullname", ["name"]],
                ["oauth_access_token", ["oauth_token"]],
            ],
        },
    },
}

##
## Our oauth handler class definition
##
class DemoLogoutHandler(OAuthMixin, Jinja2Rendering):
    def get(self):
        """Clears cookie and sends user to login page"""
        context = {
            'message': "%s is logged out!" % self.current_user,
        }
        self.delete_cookies()
        self.set_status(200)
        return self.render_template('success.html', **context)


##
## Our oauth handler class definition
##
class DemoProtectedHandler(OAuthMixin, Jinja2Rendering):
    
    def get(self):
        """Simply let's the user know they are authenticated"""
        context = {
            'message': "%s is authenticated!" % self.current_user,
        }
        self.set_status(200)
        return self.render_template('success.html', **context)

##
## Our oauth handler class definition
##
class DemoHandler(Jinja2Rendering):
    """our index page"""
    @lazyprop
    def current_user(self):
        """get our current_user"""
        return self.get_cookie('username', None) 

    @lazyprop
    def session_id(self):
        """get our SESSID. This is our session cookie"""
        return self.get_argument('SESSID', None)

    def get(self):
        """Simply let's the user know they are authenticated or not."""
        context = {
            'message': "%s is authenticated!" % self.current_user,
        }
        self.set_status(200)
        return self.render_template('index.html', **context)

##
## Our oauth handler class definition
##
class DemoOAuthHandler(Jinja2Rendering, OAuthMixin):
    """our qoorate specific oAuth handler"""
    ## Define these if you do not want to use redis to persist data thoughout the oauth request"""
    #datahandler = {
    #    "default": (MyOAuthQueries, oAuthModel),
    #    "oauth": (MyUserQueries, UserModel)
    #}

    def prepare(self):
        self.user_queryset = application_user_queryset

    @lazyprop
    def current_user(self):
        """get our current_user"""
        return self.get_cookie('username', None) 

    @lazyprop
    def session_id(self):
        """get our SESSID
        This is our session cookie
        """
        return self.get_argument('SESSID', None)

    def onAuthenticationSuccess(self, oauth_request_model):
        """it is the applications responsibilty to extend this class and
        implement this method. It may be empty if you simply care about authentication.
        The oAuth object used to uathenticate is also accessible with self.oauth
        """
        # first try to get our user based on aouth_id and oauth_provider
        oauth_data = json.loads(oauth_request_model.data)
        username = (oauth_data["username"] if "username" in oauth_data and oauth_data["username"] != '' else
            oauth_data["name"] if "name" in oauth_data and oauth_data["name"] != '' else
            oauth_data["fullname"] if "fullname" in oauth_data and oauth_data["fullname"] != '' else None)
        
        if username == None:
            raise Exception("No UserName found in oauth_data 'username','name' or 'fullname' fields.")            

        self._username = username
        self.set_cookie('username', self.username) 

        context = {
            'message': "Thank You!",
        }
        self.set_status(200)
        return self.render_template('loggedin.html', **context)

class BrubeckOAuthDemo(Brubeck):
    """this just feels usefull, worth doing"""