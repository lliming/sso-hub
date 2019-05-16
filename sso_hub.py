#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, url_for, session, redirect, request, render_template
import globus_sdk
from globus_sdk import (GlobusError,GlobusAPIError)
import json
import time


app = Flask(__name__)
app.config.from_pyfile('sso_hub.conf')

@app.route('/')
def index():
    # Call get_login_status() to fill out the login status variables (for login/logout display)
    loginstatus = get_login_status()

    # If not logged in, welcome and invite to login
    if not session.get('is_authenticated'):
         return render_template(app.config['APP_LOGIN_TEMPLATE'],
                                pagetitle=app.config['APP_DISPLAY_NAME'],
                                loginurl=url_for('login'),
                                loginstat=loginstatus)

    # If logged in, display XSEDE identity info and choice of login services
    return render_template('choose-login-service.html',
         pagetitle=app.config['APP_DISPLAY_NAME'],
         loginstat=loginstatus)


@app.route('/login')
def login():
    """
    Login via Globus Auth.
    May be invoked in one of two scenarios:

      1. Login is starting, no state in Globus Auth yet
      2. Returning to application during login, already have short-lived
         code from Globus Auth to exchange for tokens, encoded in a query
         param
    """
    # the redirect URI, as a complete URI (not relative path)
    redirect_uri = url_for('login', _external=True)

    auth_client = load_app_client()
    auth_client.oauth2_start_flow(redirect_uri, 
            requested_scopes='openid email profile')

    # If there's no "code" query string parameter, we're in this route
    # starting a Globus Auth login flow.
    # Redirect out to Globus Auth
    if 'code' not in request.args:
        auth_uri = auth_client.oauth2_get_authorize_url()
        return redirect(auth_uri)
    # If we do have a "code" param, we're coming back from Globus Auth
    # and can start the process of exchanging an auth code for a token.
    else:
        code = request.args.get('code')
        tokens_response = auth_client.oauth2_exchange_code_for_tokens(code)

        # Get the id_token (ids) that tells us who this user is (for the login/logout display)
        id_token = tokens_response.decode_id_token()

        session.update(
                userid=id_token['sub'],
                identity=id_token['preferred_username'],
                fullname=id_token['name'],
                is_authenticated=True
                )
        return redirect(url_for('index'))

@app.route("/logout")
def logout():
    """
    - Destroy the session state.
    - Redirect the user to the Globus Auth logout page.
    """

    # Destroy the session state
    session.clear()

    # the return redirection location to give to Globus AUth
    redirect_uri = url_for('index', _external=True)

    # build the logout URI with query params
    # there is no tool to help build this (yet!)
    globus_logout_url = (
        'https://auth.globus.org/v2/web/logout' +
        '?client_id={}'.format(app.config['APP_CLIENT_ID']) +
        '&redirect_uri={}'.format(redirect_uri) +
        '&redirect_name={}'.format(app.config['APP_DISPLAY_NAME']))

    # Redirect the user to the Globus Auth logout page
    return redirect(globus_logout_url)


@app.route("/privacy")
def privacy():
    # Call get_login_status() to fill out the login status variables (for login/logout display)
    loginstatus = get_login_status()

    return render_template('privacy.html', 
                           loginstat=loginstatus,
                           pagetitle=app.config['APP_DISPLAY_NAME'],
                           returnurl=url_for('index'))

def load_app_client():
    return globus_sdk.ConfidentialAppAuthClient(
        app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'])

def get_login_status():
    # This function returns a dictionary containing login information for the current session.
    # It is used to populate the login section of the UI.
    loginstat = dict()
    if not session.get('is_authenticated'):
         # prepare an empty status
         loginstat["status"] = False
         loginstat["loginlink"] = url_for('login')
         loginstat["logoutlink"] = ''
         loginstat["fullname"] = ''
         loginstat["identity"] = ''
    else:
         # User is logged in
         loginstat["status"] = True
         loginstat["loginlink"] = ''
         loginstat["logoutlink"] = url_for('logout', _external=True)
         loginstat["fullname"] = str(session.get('fullname'))
         loginstat["identity"] = str(session.get('identity'))
    return loginstat


# actually run the app if this is called as a script
if __name__ == '__main__':
    app.run(host='0.0.0.0',port=5000,debug=True,ssl_context=('./keys/server.crt', './keys/server.key'))

