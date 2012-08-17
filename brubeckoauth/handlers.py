#!/usr/bin/env python
import sys
import urllib2
import functools
import logging
import os
import time
import md5
import base64
import hmac
import hashlib
import httplib
import random
import json
import datetime
import imp
import uuid

import requests
from urllib import unquote, quote
from brubeck.auth import authenticated
from brubeck.queryset import DictQueryset
from brubeck.request_handling import Brubeck, WebMessageHandler, JSONMessageHandler, cookie_encode, cookie_decode
from brubeck.templating import load_jinja2_env, Jinja2Rendering
from dictshield import fields
from dictshield.document import Document
from dictshield.fields import ShieldException

from models import OAuthRequest
from base import lazyprop, OAuthBase

## RedisQueryset is used if available
## Otherwise DictQueryset will be used which only
## works with a single Brubeck instance architecture
## You can overide g_oauth_request_queryset
## with you own implementation.
## we default to DictQueryset for now since we don't have access
## to the applications settings.
global g_oauth_request_queryset
g_oauth_request_queryset = DictQueryset()

## add redis support if available
global redis_available
redis_available = False
try:
    import redis
    from redis.exceptions import ConnectionError
    from brubeck.queryset import RedisQueryset
    redis_available = True
except Exception:
    logging.info("Redis module not found (single instance mode: using in memory buffer)")
    pass


##################################################
# Test handler 
##################################################
class OAuthRedirectorTestHandler(object):
    """Our development oAuth handler.
    parses a predifined callback from oAuth[PROVIDERS][{providername}]
    """
    def get(self, settings):
        # we are in development, fake it
        logging.debug( "facebook faking it" );
        user = find_user_by_username(self.username)
        oauth_data = settings['TEST_OAUTH_DATA']
        # we should store this data now
        if user == None:
            user = User(
                username=self.username,
                nickname=oauth_data['username'],
                current_oauth_provider='facebook',
                oauth_data=json.dumps(oauth_data)
            )
        else:
            user.nickname = oauth_data['username']
            user.current_oauth_provider = 'facebook'
            user.oauth_data = json.dumps(oauth_data)
        
        # adding an existing key just replaces it
        add_user(user)
        return self.redirect("/oauth/facebook/loggedin")


###############################################
# The handler mixin we actualy use for routing
###############################################

class OAuthMixin(object):
    """oauth routing handler mixin. All requests come through here.
    You should use this as a mixin for your WebMessageHandler and 
    implement the methods onAuthenticationSuccess and 
    onAuthenticationFailure.
    """

    @lazyprop
    def settings(self):
        """used to define the supported providers configurations"""
        return self.application.get_settings('oauth')

    @lazyprop
    def oauth_token(self):
        """ oauth_token argument.
        used by oauth1a to track request and response to same user.
        """
        return self.get_argument('oauth_token', None)

    @lazyprop
    def oauth_error(self):
        """ error argument.
        used by oauth2 to send an error message back the calling application.
        """
        return self.get_argument('error', None)

    @lazyprop
    def state(self):
        """ state argument.
        used by oauth2 to track request and response to same user.
        """
        return self.get_argument('state', None)

    @lazyprop
    def code(self):
        """ code argument.
        used by oauth2 to track request and response to same user.
        """
        return self.get_argument('code', None)

    @lazyprop
    def oauth_verifier(self):
        """ argument returned by auth calls
        """
        return self.get_argument('oauth_verifier', None)

    @lazyprop
    def oauth_base(self):
        """ Our oAuth base object (not oauth version specific).
        """
        return OAuthBase()

    @lazyprop
    def oauth_request_model(self):
        """ Our model containing state from the oauth request process.
        """
        model = None

        if self.oauth_token != None:
            logging.debug("self.oauth_token: %s" % (self.oauth_token))
            results = self.oauth_request_queryset.read_one(self.oauth_token)
            logging.debug("results: %s" % (len(results)))
            logging.debug("results[0]: %s" % (results[0]))
            logging.debug("results[1]: %s" % (results[1]))
            data = results[1]
            if results[0] != self.oauth_request_queryset.MSG_FAILED:
                logging.debug("data: %s" % (data))
                model = OAuthRequest(**data)
            else:
                logging.debug("oauth_request_model not found: %s" % (data))
        elif self.state != None:
            logging.debug("oauth_request_model using state: %s" % (self.state))
            results = self.oauth_request_queryset.read_one(self.state)
            logging.debug("results: %s" % (len(results)))
            logging.debug("results[0]: %s" % (results[0]))
            logging.debug("results[1]: %s" % (results[1]))
            if results[0] != self.oauth_request_queryset.MSG_FAILED:
                data = results[1]
                logging.debug("data: %s" % (data))
                model = OAuthRequest(**data)
            else:
                logging.debug("oauth_request_model not found: %s" % data)
        elif self.denied != None:
            logging.debug("no oauth_token, denied")
            logging.debug("self.denied: %s" % (self.denied))
            results = self.oauth_request_queryset.read_one(self.denied)
            logging.debug("results: %s" % (len(results)))
            logging.debug("results[0]: %s" % (results[0]))
            logging.debug("results[1]: %s" % (results[1]))
            data = results[1]
            if results[0] != self.oauth_request_queryset.MSG_FAILED:
                logging.debug("data: %s" % (data))
                model = OAuthRequest(**data)
            else:
                logging.debug("oauth_request_model not found: %s" % (data))
        else:
            logging.debug("no oauth_token, state or denied argument returned")

        if model == None:
            raise Exception("oAuthRequest model not found on return from callback.")

        return model

    @lazyprop
    def oauth_token(self):
        """ oauth_token argument sent by the provider
        """
        return self.get_argument('oauth_token', None)

    @lazyprop
    def denied(self):
        """ denied argument sent by the provider (will ne oauth_toeken to retrieve user data
        """
        return self.get_argument('denied', None)

    @lazyprop
    def oauth_request_queryset(self):
        """ the queryset to manage our oauuth_request persistance
        (defaults to in memory DictQueryset).
        """
        global g_oauth_request_queryset
        if redis_available and "REDIS" in self.settings:
            redis_settings = self.settings["REDIS"]
            try:
                # set our default host and port
                host="127.0.0.1"
                port=6379

                if "HOST" in redis_settings:
                    host = redis_settings["HOST"]
                else:
                    logging.info("Redis setting HOST not dound, using default: %s" % host)

                if "PORT" in redis_settings:
                    port = redis_settings["PORT"]
                else:
                    logging.info("Redis setting PORT not found, using default: %s" % port)

                redis_server = redis.Redis(host=host, port=port, db=0)

                if redis_server.echo("connected") == "connected":
                    g_oauth_request_queryset = RedisQueryset(**{"db_conn": redis_server})
                    logging.debug("Redis server connected (%s:%s)" % (host, port))
            except ConnectionError as ce:
                logging.info("Redis ConnectionError (%s:%s): %s" % (host, port, ce.message))
                logging.info("BrubeckOAuth using single instance mode: using in memory buffer)")
                pass
            except Exception as e:
                logging.info("Redis Exception (%s:%s): %s" % (host, port, e.message))
                logging.info("BrubeckOAuth using single instance mode: using in memory buffer)")
                pass
        return g_oauth_request_queryset

    def get(self, provider, action):
        """Loads the provider config and 
        routes our request to the proper base methods.
        """
        try:
            logging.debug("oauth GET %s %s" % (provider, action))
            # logging.debug(self.settings)
            # see if we are in test mode
            if ("OAUTH_TEST" in self.settings and
                self.settings["OAUTH_TEST"] == True):
                # skip all the formalities and use our canned response
                return OAuthRedirectorTestHandler.get(self, self.settings)
            if not provider in self.settings['PROVIDERS']:
                raise Exception("Unsupported provider: %s" % provider)
            provider_settings = self.settings['PROVIDERS'][provider]            
            logging.debug("provider_settings -> \n%s" % provider_settings)
            oauth_object = self.oauth_base.get_oauth_object(provider_settings)
            # respond to the proper action
            if action == 'login':

                # application hook
                result = self.onBeforeRedirect(provider_settings)
                if self._finished:
                    return result
                
                return self.redirect(oauth_object.redirector(provider_settings,
                    self.oauth_request_queryset,
                    self.session_id,
                    self.message.arguments))
            elif action == 'callback':
                # merge our initial arguments for the oauth request 
                # before redirection to provider with response from provider.
                # this allows us to keep state after login
                initial_args = json.loads(self.oauth_request_model.initial_request_args)
                self.message.arguments.update(initial_args)
                logging.debug('Merged arguments: %s' % json.dumps(self.message.arguments));
                if self.oauth_error == None and (self.oauth_token != None or self.state != None):
                    self._oauth_request_model = oauth_object.callback(
                        provider_settings,
                        self.oauth_request_model, 
                        self.oauth_token, 
                        self.oauth_verifier,
                        self.session_id,
                        self.message.arguments
                    )
                    return self.onAuthenticationSuccess(self.oauth_request_model)
                elif self.denied != None or self.oauth_error == 'access_denied':
                    return self.onAuthenticationFailure(self.oauth_request_model)
                elif self.code == None:
                    return self.onAuthenticationError(self.oauth_request_model)
            else:
                raise Exception("Unsupported action: " + action)
        except Exception as e:
            raise
            self.set_status(200)
            self.add_to_payload('messages', e)
            return self.render()
        # if we got here, we have problems
        self.set_status(403)
        self.add_to_payload('messages', "Unknown oauth error")
        return self.render();

    def onBeforeRedirect(self, provider_settings):
        """This gives us a chance to do some validation before we go to oauth
        """
        logging.debug("onBeforeRedirect hook empty.")
        pass

    def onAuthenticationSuccess(self, oauth_request_model):
        """it is the applications responsibilty to extend this class and
        implement this method to hook into the rest of the applications 
        authentication and user handling.
        The oauth_request_model is by default 
        not persisted beyond this function.
        """
        raise NotImplementedError

    def onAuthenticationFailure(self, oauth_request_model):
        """Failure is harsh, deal with it more gracefully if you want to.
        """
        raise Exception("Authentication failed!")

    def onAuthenticationError(self, oauth_request_model):
        """Error are harsher, and more mysterious, deal with it more gracefully if you want to.
        """
        raise Exception("Unknown authentication error!")
