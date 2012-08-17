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
import datetime
import imp
import uuid
import json

import requests
from brubeck.auth import authenticated
from brubeck.templating import load_jinja2_env, Jinja2Rendering
from dictshield import fields
from dictshield.document import Document
from dictshield.fields import ShieldException
from urllib import unquote, quote

from models import OAuthRequest

  
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


class OAuthBase(object):
    """Our OAuthBase message handlers base class.
    This is extended by OAuth classes written for specific versions.
    """

    @lazyprop
    def oauth1a_object(self):
        """ Our OAuth 1.0a implementation"""
        return OAuth1aObject()

    @lazyprop
    def oauth2_object(self):
        """ Our OAuth 2.0 implementation"""
        return OAuth2Object()

    def get_user_info(self, provider_settings, oauth_token,
                      oauth_request_model):
        """gets additional userinfo after authenticating.
        Uses USER_INFO from the oauth config file.
        It calls map_date to map provider specific data to
        application specific values.
        """
        user_infos = provider_settings['USER_INFO']
        for user_info in user_infos:
            url = user_info[0]
            signature_args = {
                'oauth_token': oauth_token
            }
            request_args = {}
            kvs = self._request(provider_settings, 'GET', url, request_args,
                                oauth_request_model, signature_args)
            if 'response' in kvs:
                # Some providers mave `meta` and `response` 
                # wrappers for what is returned.
                kvs = kvs['response']
            fields = user_info[1]
            kvs = self.map_data(kvs, fields)
        return kvs

    def map_data(self, data, fields):
        """Map our returned values to application specific labels
        This way we can respond to an auth request
        generically in the application
        """
        for field in fields:
            value = data
            # a field is a list with the following items
            # 1. The name of the attribute to save
            #    in the oauth_data dict (required) ie. "auth_id"
            # 2. A list of attribute to get the value from. (required)
            #   i.e ['user','id'] would get the users
            #   name attribute from a JSON request
            #   This may also be a list of lists.
            #   This would take multiple values and join them
            # 3. A format string to apply the final value to.
            #   i.e. "https://graph.facebook.com/%s/picture"
            #   this allows us to do things like create the
            #   profile image url from the oauth id for facebook
            # Examples:
            # 1. Build a url for a thumbnail.
            # ["thumbnailLarge", ["id"],
            #  "https://graph.facebook.com/%s/picture"]
            #
            # 2. Create a full name from first and last.
            # ["fullname", [["first"],["last"]], "%s %s"]
            #
            field_name = field[0]
            field_descriptors = field[1]
            field_formatter = field[2] if len(field) > 2 else None
            logging.debug("user_info field: %s" % field_name)
            # get our value
            values = []
            i = 0
            if isinstance(field_descriptors[0], list):
                logging.debug("user_info compound field value")
                for descriptors in field_descriptors:
                    values.append('')
                    for descriptor in descriptors:
                        values[i] = value[descriptor] if (value != None and
                                    descriptor in value) else None
                    i+=1
            else:
                logging.debug("user_info simple field value")
                values.append(value)
                for descriptor in field_descriptors:
                    values[0] = value[descriptor] if (value != None and
                                descriptor in value) else None
            # Make sure a Non value doesn't blow us up
            def safe_values(value):
                if value == None:
                    return ''
                else:
                    return str(value)
            # format our field if needed
            if value != None:
                if field_formatter != None:
                    values = tuple(values)
                    logging.debug("user_info formating '%s' with %s" %
                                  (field_formatter, values))
                    value = field_formatter % values
                else:
                    logging.debug("user_info joining %s" % (values))
                    value = "".join(map(safe_values, values))
            logging.debug("user_info field[0], value: %s, %s" %
                          (field_name, value))
            data.update({ field_name: value })
        # return our data with the new values appended
        return data

    def get_oauth_object(self, provider_settings):
        """returns the proper oauth object to use for
        the version specified in provider_settings"""
        ver = provider_settings['OAUTH_VERSION']
        if ver == '2.0':
            return self.oauth2_object
        elif ver == '1.0a':
            return self.oauth1a_object
        else:
            raise Exception("Unsupported oAuth version: %s" %
                            provider_settings['OAUTH_VERSION'])

    def _parse_content(self, content):
        """Parses a key value pair or JSON string into a dict"""
        kv_dict = {}
        if content == None:
            return kv_dict
        if content[0] == '{':
            # assume JSON
            kv_dict = json.loads(content)
        else:
            kv_dict = dict(u.split('=') for u in content.split('&'))
        return kv_dict

    def request(self, provider_settings, method, url, request_args,
                oauth_request_model):
        """this is a simple wrapper to _request that should be
        used by the client. This is used to make authenticated requests
        after a user is logged in.
        """
        return self._request(provider_settings, method, url, request_args,
                             oauth_request_model, {})
            
    def _request(self, provider_settings, method, url, request_args,
                 oauth_request_model=None, signature_args={}):
        """it is each auth version specifics class to implement this"""
        raise NotImplementedError

    def redirector(self, provider_settings, oauth_request_queryset,
                   session_id, arguments):
        """it is each auth version specifics class to implement this"""
        raise NotImplementedError

    def callback(provider_settings, oauth_request_model, oauth_token,
                 oauth_verifier, session_id, **kw):
        """it is each auth version specifics class to implement this"""
        raise NotImplementedError

##################################################
# oAuth 1.0a logic (yucky)
##################################################
class OAuth1aObject(OAuthBase):
    """Handles oAuth 1.0a authentication"""
    def _signature_base_string(self, http_method, base_uri,
                               query_params, delimiter = "%26"):
        """Creates the base string for an authorized request"""
        query_string = ''
        keys = query_params.keys()
        keys.sort()
        for param in keys:
            if param != '':
                if query_string != '':
                    query_string = "%s%s" % (query_string, delimiter)
                query_string = "%s%s" % (query_string,
                                         quote("%s=%s" %(
                                                    quote(param, ''),
                                                    quote(query_params[param],
                                                          '')
                                                ),
                                               '')
                                         )
        return "%s&%s&%s" % (http_method, quote(  base_uri, '' ), query_string)

    def _sign(self, secret_key, base_string ):
        """Creates a HMAC-SHA1 signature"""
        digest = hmac.new(secret_key, base_string, hashlib.sha1).digest()
        return base64.encodestring(digest).rstrip()

    def _authorization_header(self, query_params):
        """Build our Authorization header."""
        authorization_header = 'OAuth'
        keys = query_params.keys()
        keys.sort()
        for param in keys:
            if param != '':
                authorization_header = "%s %s=\"%s\"," % (
                                            authorization_header,
                                            param,
                                            quote( query_params[param], '')
                                        )
        authorization_header = authorization_header.rstrip(',')
        return authorization_header

    def _generate_nonce(self):
        """Generates a nonce."""
        random_number = ''.join(str(random.randint(0, 9)) for i in range(40))
        m = md5.new(str(time.time()) + str(random_number))
        return m.hexdigest()

    def _request(self, provider_settings, http_method, url, request_args,
                 oauth_request_model=None, signature_args={}):
        """make a signed request for given provider_settings
        given a url and optional parameters.
        The following parameters are not needed in optional:
        oauth_consumer_key,oauth_nonce,oauth_signature_method,
        oauth_timestamp,oauth_version"""
        oauth_secret = ''
        if (oauth_request_model != None and 
           oauth_request_model.token_secret != None):
            oauth_secret = oauth_request_model.token_secret
        logging.debug( "_request oauth_secret: %s" % oauth_secret );
        oauth_timestamp = str(int(time.time()))
        oauth_nonce = self._generate_nonce()
        oauth_consumer_secret = provider_settings['CONSUMER_SECRET']
        oauth_consumer_key = provider_settings['CONSUMER_KEY']
        query_params = {
            'oauth_consumer_key': oauth_consumer_key,
            'oauth_nonce': oauth_nonce,
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp': oauth_timestamp,
            'oauth_version': '1.0'
        }
        if request_args != None:
            if oauth_request_model != None:
                logging.debug( "oauth_token: %s" % oauth_request_model.token );
                query_params['oauth_token'] = oauth_request_model.token
        else:
            request_args = {}
        # add optional parameters
        query_params.update(signature_args)
        query_params.update(request_args)
        logging.debug("query_params -> \n%s" % query_params)
        signature_base_string = self._signature_base_string(http_method, url, 
                                                            query_params)
        signature_key = oauth_consumer_secret + "&" + oauth_secret
        oauth_signature = self._sign(signature_key, signature_base_string)
        logging.debug("signature_base_string: %s" % signature_base_string);
        logging.debug("signature_key: %s" % signature_key);
        logging.debug("oauth_signature: %s" % oauth_signature);
        query_params.update({'oauth_signature': oauth_signature});
        authorization_header = self._authorization_header(query_params)
        logging.debug('Authorization: ' + authorization_header + "\n\n")
        try:
            if http_method == 'POST':
                response = requests.post(
                    url, request_args, 
                    **{'headers': {'Authorization': authorization_header}} 
                )
            else:
                response = requests.get(
                    url, params = request_args,
                    headers = {'Authorization': authorization_header}
                )
            content = response.content
            logging.debug("content -> \n%s" % content);
            if content[0:9] == '<!DOCTYPE':
                raise Exception(content)
            if content.rfind('&') == -1 and content.rfind('{') == -1:
                raise Exception(content);
            kv_pairs = self._parse_content(content);
        except Exception:
            raise
        return kv_pairs

    def redirector(self, provider_settings, oauth_request_queryset, session_id, arguments):
        """gets the token and redirects the user to the oauth login page"""
        try:
            url = provider_settings['REQUEST_TOKEN_URL']
            oauth_callback = provider_settings['CALLBACK_URL']
            logging.debug("oauth_callback: %s" % oauth_callback);
            signature_args = {
                'oauth_callback': oauth_callback
            }
            kv_pairs = self._request(
                provider_settings, 'POST', url,
                {}, None, signature_args
            )
            oauth_token = ''
            token_secret = ''
            # save our data
            if 'oauth_token' in kv_pairs:
                oauth_token = kv_pairs['oauth_token']
                if 'oauth_token_secret' in kv_pairs:
                    token_secret = kv_pairs['oauth_token_secret']
                    logging.debug("token_secret: " + token_secret)
                data = {
                    'api_id': oauth_token,
                    'id': oauth_token,
                    'token_secret': token_secret,
                    'session_id': session_id,
                    'token': oauth_token,
                    'provider_tag': provider_settings['PROVIDER_TAG'],
                    'provider': provider_settings['PROVIDER_NAME'],
                    'data': json.dumps(kv_pairs),
                    'initial_request_args': json.dumps(arguments),
                }
                logging.debug("data -> \n%s" % data)
                oauth_request_model = OAuthRequest(**data)
                oauth_request_queryset.create_one(oauth_request_model)
                return "%s?oauth_token=%s" % (
                        provider_settings['AUTHORIZE_URL'],
                        kv_pairs['oauth_token']
                       )
        except Exception:
            raise
        # we shouldn't get here
        raise Exception('message', 'an unknown error occured')

    def callback(self, provider_settings, oauth_request_model, 
                 oauth_token, oauth_verifier, session_id, arguments):
        """handle an oAuth 1.0a callback"""
        """this is always called "statically" from OAuthHandler"""
        try:
            url = provider_settings['ACCESS_TOKEN_URL']
            logging.debug( "oauth_token: %s" % oauth_token );
            logging.debug( "oauth_verifier: %s" % oauth_verifier );
            signature_args = {
                'oauth_token':oauth_token,
                'oauth_verifier':oauth_verifier
            }
            kv_pairs = self._request(provider_settings, 'POST', url,
                                     {}, oauth_request_model, signature_args)
            if 'oauth_token' in kv_pairs:
                # get our additional user data
                user_infos = provider_settings['USER_INFO'];
                oauth_token = kv_pairs['oauth_token'];
                oauth_token_secret = kv_pairs['oauth_token_secret'];
                oauth_request_model.token = oauth_token
                oauth_request_model.token_secret = oauth_token_secret
                oauth_request_model.data = json.dumps(kv_pairs)
                kvs = self.get_user_info(provider_settings,
                                         oauth_token,
                                         oauth_request_model)
                kv_pairs.update(kvs)
                # process any aliases on the final data
                if "ALIASES" in provider_settings:
                    kv_pairs = self.map_data(kv_pairs, 
                                             provider_settings["ALIASES"])
                # save our data
                logging.debug("data -> \n%s " % kv_pairs)
                oauth_request_model.data = json.dumps(kv_pairs)
                return oauth_request_model
            else:
                raise Exception("Not authenticated")
        except Exception:
            raise
        raise Exception("Unknow oAuth error")


##################################################
# oAuth 2.0 methods
##################################################
class OAuth2Object(OAuthBase):
    """Methods needed for  oAuth 2.0 authentication"""
    def _request(self, provider_settings, http_method, url, request_args={},
                 oauth_request_model=None, signature_args={}):
        """make a signed request for given provider_settings 
        given a url and optional parameters.
        The following parameters are not needed in optional:
        oauth_consumer_key,oauth_nonce,oauth_signature_method,
        oauth_timestamp,oauth_version
        params are not required or used for oauth2
        """
        # For oAuth2 request_args and signature_args are treated the same.
        request_args.update(signature_args);
        try:
            if http_method == 'POST':
                response = requests.post(url, request_args)
            else:
                response = requests.get(url, params = request_args)
            content = response.content
            logging.debug("content: %s" % content);
            if content[0:9] == '<!DOCTYPE':
                raise Exception(content)
            if content.rfind('&') == -1 and content.rfind('{') == -1:
                raise Exception(content);
            kv_pairs = self._parse_content(content);
        except Exception:
            raise
        return kv_pairs

    def redirector(self, provider_settings,
                   oauth_request_queryset, session_id, arguments):
        """Handles the redirect to an oauth provider"""

        oauth_request_model_id = str(uuid.uuid1())
        logging.debug('oauth_request_model_id: %s' % (
                            oauth_request_model_id
                        )
                     )
        logging.debug("initial_arguments: %s" % json.dumps(arguments))
        data = {
            'api_id': oauth_request_model_id,
            'id': oauth_request_model_id,
            'session_id': session_id,
            'token_secret': '',
            'token': '',
            'provider_tag': provider_settings['PROVIDER_TAG'],
            'provider': provider_settings['PROVIDER_NAME'],
            'data': '',
            'initial_request_args': json.dumps(arguments),
        }
        oauth_request_model = OAuthRequest(**data)
        oauth_request_queryset.create_one(oauth_request_model)
        url = provider_settings['REQUEST_URL']
        query_params = {
            'state' : oauth_request_model_id,
            'client_id' : provider_settings['APP_ID'],
            'scope' : provider_settings['SCOPE'],
            'redirect_uri' : provider_settings['REDIRECT_URL']
        }
        if 'REQUEST_URL_ADDITIONAL_PARAMS' in provider_settings:
            query_params.update(
                provider_settings['REQUEST_URL_ADDITIONAL_PARAMS']
            )
        query_string = '';
        for key in query_params:
            logging.debug("query_params key: %s" % key)
            if query_string == '':
                query_string += '?'
            else:
                query_string += '&'
            query_string += (key + '=' + query_params[key])
        url += query_string
        # send user to oauth login
        logging.debug("%s url %s" % 
                      (provider_settings['PROVIDER_NAME'], url))
        return url

    def callback(self, provider_settings, oauth_request_model,
                 oauth_token, oauth_verifier, session_id, arguments):
        """Handle the callback from an oauth provider"""
        # we came from a callback and have our oauth_request_token
        oauth_request_model_id = arguments['state']
        code = arguments['code']
        logging.debug("oauth callback: state = %s" %
                      oauth_request_model_id )
        url = provider_settings['ACCESS_TOKEN_REQUEST_URL']
        logging.debug('client_id: %s' % provider_settings['APP_ID'])
        logging.debug('redirect_uri: %s' % provider_settings['REDIRECT_URL'])
        logging.debug('client_secret: %s' % provider_settings['APP_SECRET'])
        logging.debug('code: %s'  % code);
        query_params = {
            'client_id': provider_settings['APP_ID'],
            'redirect_uri': provider_settings['REDIRECT_URL'],
            'client_secret': provider_settings['APP_SECRET'],
            'code': code
        }
        if 'ACCESS_TOKEN_REQUEST_ADDITIONAL_PARAMS' in provider_settings:
            query_params.update(
                provider_settings['ACCESS_TOKEN_REQUEST_ADDITIONAL_PARAMS']
            )
        kv_pairs = self._request(provider_settings, "POST", url, query_params)
        if 'access_token' in kv_pairs:
            access_token = kv_pairs['access_token']
            logging.debug("access_token: %s" % access_token)
            kvs = self.get_user_info(provider_settings, 
                                     access_token, 
                                     oauth_request_model)
            kv_pairs.update(kvs)
            # add any aliases to the final data
            if "ALIASES" in provider_settings:
                kv_pairs = self.map_data(kv_pairs,
                                         provider_settings["ALIASES"])
            oauth_data = json.dumps(kv_pairs)
            # we should store this data now
            logging.debug("oauth_data: %s" % oauth_data);
            oauth_request_model.data = oauth_data
            return oauth_request_model
        else:
            raise Exception("Not Authenticated")
        raise Exception("Unknown oAuth error")
