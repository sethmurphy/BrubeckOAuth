#!/usr/bin/env python
# Copyright 2012 Brooklyn Code Incorporated. See LICENSE.md for usage
# the license can also be found at http://brooklyncode.com/LICENSE.md
import json
import datetime
import time

from schematics import types
from schematics.models import Model
from schematics.types.mongo import ObjectIdType
#from bson.objectid import ObjectId
##
## Our Schematics class defintions
##

class OAuthRequest(Model):

    id = types.StringType()
    """used to track an auth authentication session"""
    #id = fields.StringField(required=True, max_length=1024, id_field=True)
    api_id = types.StringType(required=True, max_length=255)
    session_id = types.StringType(required=True, max_length=1024)
    token_secret = types.StringType(required=True, max_length=1024)
    token = types.StringType(required=True, max_length=1024)
    provider = types.StringType(required=True, max_length=255)
    provider_tag = types.StringType(required=True, max_length=2)
    data = types.StringType(required=True, max_length=5000)
    initial_request_args = types.StringType(required=True, max_length=5000)
    error_message = types.StringType(required=True, max_length=255)

    def __init__(self, *args, **kwargs):
        super(OAuthRequest, self).__init__(**kwargs)
