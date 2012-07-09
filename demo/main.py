##
## runtime configuration
##
import sys
import os
import logging

from brubechoauthdemo import DemoOAuthHandler

## Turn on some debugging
logging.basicConfig(level=logging.DEBUG)

project_dir = '.'
logging.info("Using project directory: " + project_dir)

config = {
    'mongrel2_pair': ('ipc://run/mongrel2_send', 'ipc://run/mongrel2_rcv'),
    'handler_tuples': [ ## Set up our routes
        (r'^/oauth/(?P<provider>.+)/(?P<action>.+)$', DemoOAuthHandler),
        (r'^/logout', DemoLogoutHandler),
        (r'^/protected', DemoProtectedHandler),
        (r'^/', DemoLoginHandler),
    ],
    'cookie_secret': '_1sRe%%66a^O9s$4c6ld!@_F%&9AlH)-6OO1!',
    'template_loader': load_jinja2_env( project_dir + '/templates'),
    'log_level': logging.DEBUG,
}


##
## get us started!
##
app = Brubeck(**config)
## start our server to handle requests
if __name__ == "__main__":
    app.run()
