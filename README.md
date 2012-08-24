
BrubeckOAuth
------------
This is an integration of oAuth for Brubeck. You must use an Object Handler in order to implement this into your project. The basic steps are as follows:

 - Create a Config
 - Extend the BrubeckOAuth Handler with your own.

BrubeckOAuth Settings
---------------------

In order to get your settings into the handler it is assumed your application object can have the following method called on it:
    get_settings('oauth')

The above return the following oauth Dict:

    oauth = {
        ## This is optional, but highly recommended and required if you run more than one Brubeck instance
        "REDIS": {
            "HOST": "localhost",
            "PORT": 6379,
        },
        
        # Configuration of 2 supported providers, one of each type
        "PROVIDERS": {
            "facebook": {
                "PROVIDER_NAME": "facebook",
                "PROVIDER_TAG": "fb",
                "OAUTH_VERSION": "2.0",
                "APP_ID": "[YOUR APP ID HERE]",
                "APP_SECRET": "[YOUR APP SECRET HERE]",
                "SCOPE": "user_about_me, email, user_location, publish_stream",
                "REDIRECT_URL": "[YOUR CALLBACK URL HERE]",
                "REQUEST_URL": "https://www.facebook.com/dialog/oauth",
                "REQUEST_URL_ADDITIONAL_PARAMS": {"display" : "popup"}, 
                "ACCESS_TOKEN_REQUEST_URL": "https://graph.facebook.com/oauth/access_token",
                "USER_INFO": [  
                    ["https://graph.facebook.com/me", 
                        [
                            ["username", ["username"]], 
                            ["name", ["name"]], 
                            ["fullname", [["first_name"],["last_name"]], "%s %s"], 
                            ["oauth_uid", ["id"]],
                            ["thumbnailLarge", ["id"], "https://graph.facebook.com/%s/picture"],
                        ],
                    ],
                ],
                "ALIASES": [
                    ["oauth_access_token", ["access_token"]],
                    ["thumbnail", ["thumbnailLarge"]],
                ],
            },
            
            "twitter": {
                "PROVIDER_NAME": "twitter",
                "PROVIDER_TAG": "tw",
                "OAUTH_VERSION": "1.0a",
                "CONSUMER_KEY": "[YOUR APP ID HERE]",
                "CONSUMER_SECRET": "[YOUR APP SECRET HERE]",
                "REQUEST_TOKEN_URL": "https://api.twitter.com/oauth/request_token",
                "REQUEST_TOKEN_URL_HOST": "https://api.twitter.com",
                "REQUEST_TOKEN_URL_PATH": "/oauth/request_token",
                "AUTHORIZE_URL": "https://api.twitter.com/oauth/authorize",
                "ACCESS_TOKEN_URL": "https://api.twitter.com/oauth/access_token",
                "CALLBACK_URL": "[YOUR CALLBACK URL HERE]",
                "USER_INFO": [  
                    ["https://api.twitter.com/1/account/verify_credentials.json", 
                        [
                            ["username", ["screen_name"]], 
                            ["email", ["screen_name"]], 
                            ["oauth_uid", ["id"]],
                            ["thumbnail", ["profile_image_url"]],
                        ],
                    ],
                ],
                "ALIASES": [  
                    ["fullname", ["name"]],
                    ["oauth_access_token", ["oauth_token"]],
                ],
            },
        }
    }

This module has been tested with the following providers:

  - Google Plus (2.0)
  - Facebook (2.0)
  - Twitter (1.0a)
  - Tumblr (1.0a)

BrubeckOAuthHandler
-------------------

BrubeckOAuth does not create a user or even manage a sessions authentication state, this is all up to you in your handler.

Three hooks are exposed in order for your application to intereact with the authentication process:
  onBeforeRedirect
  onAuthenticationSuccess
  onAuthenticationFailure
  onAuthenticationError

Here is an example of the simplest handler I could think of:
    #!/usr/bin/env python
    from brubeck.templating import Jinja2Rendering
    from brubeckoauth.handlers import OAuthMixin
    import json
    import logging
    ##
    ## Our example oauth handler class definition
    ##
    class ExampleOAuthHandler(Jinja2Rendering, OAuthMixin):
        """our example oAuth handler"""
    
        def onBeforeRedirect(self, provider_settings):
            """This gives us a chance to do some validation before we go to oauth
            If we don't want to continue to authentication add the following:
            Then return what you wish to be rendered.
            """
            # do some validation logic here
            # let us assume we are valid and set a flag
            allow_login = True
            if not allow_login:
                self._finished = True
                context = {
                    message: "failed login!",
                }

                return self.render_template('failed.html', **context)

        def onAuthenticationSuccess(self, oauth_request_model):
            """it is the applicatiOns responsibilty to extend this class and
            implement this method. It may be empty if you simply care about authentication.
            The oAuth object used to authenticate is also accessible with self.oauth
            You probably want to set a cookie and save/update a user. 
            You can then use this cookie to retrieve the current_user using the Brubeck Auth model
            You also have access to any arguments initially passed with the login request via normal brubeck methods.
            """
            logging.debug("onAuthenticationSuccess")
            # this is all the data returned by the provider

            oauth_data = json.loads(oauth_request_model.data)

            context = {
                message: "successful login!",
            }

            return self.render_template('success.html', **context)
    
        def onAuthenticationFailure(self, oauth_request_model):
            """We were denied access to their account.
            """
            
            context = {
                message: "failed login!",
            }

            return self.render_template('failed.html', **context)

        def onAuthenticationError(self, oauth_request_model):
            """We were denied access to their account.
            """
            
            context = {
                message: "Authentication error!",
            }

            return self.render_template('error.html', **context)

This handler would be set up with the following route:

    (r'^/oauth/(?P<provider>.+)/(?P<action>.+)$', ExampleOAuthHandler),

The following templates would be needed for the above example:

  login.html
  nologin.html
  error.html
  failure.html
  success.html

I'll leave it up to your imagination what they would contain.

More documentation to come
--------------------------

I wanted to make sure there was enough to get someone up and running who has used Brubeck before.

I will be writting a full demo soon.