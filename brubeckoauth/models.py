#!/usr/bin/env python
# Copyright 2012 Brooklyn Code Incorporated. See LICENSE.md for usage
# the license can also be found at http://brooklyncode.com/LICENSE.md
import json
import datetime
import time

from dictshield import fields
from dictshield.document import Document
from dictshield.fields.mongo import ObjectIdField
#from bson.objectid import ObjectId
##
## Our dictshield class defintions
##

class OAuthRequest(Document):

    class Meta:
        id_field = fields.StringField

    """used to track an auth authentication session"""
    #id = fields.StringField(required=True, max_length=1024, id_field=True)
    api_id = fields.StringField(required=True, max_length=255)
    session_id = fields.StringField(required=True, max_length=1024)
    token_secret = fields.StringField(required=True, max_length=1024)
    token = fields.StringField(required=True, max_length=1024)
    provider = fields.StringField(required=True, max_length=255)
    provider_tag = fields.StringField(required=True, max_length=2)
    data = fields.StringField(required=True, max_length=5000)
    initial_request_args = fields.StringField(required=True, max_length=5000)

    def __init__(self, *args, **kwargs):
        super(OAuthRequest, self).__init__(**kwargs)
