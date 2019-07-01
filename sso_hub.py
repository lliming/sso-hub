#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, url_for, session, redirect, request, render_template
import globus_sdk
from globus_sdk import (GlobusError,GlobusAPIError)
import json
import time
import re
import duo_web as duo

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

    # If logged in, display login servers for which the user has active tokens

    # First get the list of servers
    servers = get_server_list()
    if (servers == []):
         return render_template('empty-server-list.html',
                                pagetitle=app.config['APP_DISPLAY_NAME'],
                                loginstat=loginstatus)

    # Get the XSEDE username to use as a default
    match = re.search(r'([^@]*)@xsede.org',loginstatus["identity"])
    if match:
        xsedeusername = match.group(1)
    else:
        # User's effective identity isn't an XSEDE identity!
        return render_template('not-xsede-identity.html',
                                pagetitle=app.config['APP_DISPLAY_NAME'],
                                loginstat=loginstatus)

    # Build the table rows for displaying each login server
    tokenrows = ''
    ntoken = 1
    for server in servers:
        servername = server["hostname"]
        displayname = server["displayname"]
        serverid = server["resourceid"]

        # Get username on this server, or use the XSEDE username as default
        # NOTE: The local_username is currently a TBD, so this will always be the XSEDE username.
        if "local_username" in server:
            username = server["local_username"]
        else:
            username = xsedeusername

        # Is there an active token for this server?
        if "access_token" in server:
            token = server["access_token"]
            tokenrows += '<tr>\n  <td><a class="token-copy" href="" onclick="copytoken(\'token-{}\')">Copy Token</a></td>\n'.format(ntoken)
            tokenrows += '  <td><b class="displayname">{}</b><br>'.format(displayname)
            tokenrows += '      <b class="command">ssh {}@{}</b></td>\n'.format(username,servername)
            tokenrows += '  <td><input class="token-display" type="text" id="token-{}" value="{}"></td>\n</tr>\n'.format(ntoken,token)
            ntoken += 1
        else:
            tokenrows += '<tr>\n  <td><a class="activate" href="{}">Activate</a></td>\n'.format(url_for('activate',server=serverid))
            tokenrows += '  <td><b class="displayname">{}</b><br>{}</td>\n'.format(displayname,servername)
            tokenrows += '  <td></td>\n</tr>\n'

    # Display the server list and access tokens
    return render_template('show-tokens.html',
         pagetitle=app.config['APP_DISPLAY_NAME'],
         servers=json.dumps(servers,indent=3),
         tokenrows=tokenrows,
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

    # If scopes doesn't exist or is empty, initialize it to the minimum.
    if not session.get('scopes'):
        session.update(scopes = 'openid profile email')

    # Session scopes will either be minimum (set above) or will have the minumum PLUS
    # extra ssh server scopes added by server activate feature
    requested_scopes = session.get('scopes')
    
    # the redirect URI, as a complete URI (not relative path)
    redirect_uri = url_for('login', _external=True)

    auth_client = load_app_client()
    auth_client.oauth2_start_flow(redirect_uri, 
            requested_scopes=requested_scopes)

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
                scopes=requested_scopes,
                tokens=tokens_response.data,
                preauthenticated=True
                )
        return redirect(url_for('mfa'))

@app.route("/logout")
def logout():
    """
    - Revoke active tokens.
    - Destroy the session state.
    - Redirect the user to the Globus Auth logout page.
    """

    # Revoke any tokens
    if session.get("is_authenticated"):
        auth_client = load_app_client()
        # First, revoke any "other tokens," which include SSH server tokens
        for tokendata in session.get("tokens")["other_tokens"]:
            auth_client.oauth2_revoke_token(tokendata["access_token"])
        # Lastly, revoke the current Auth API access token
        auth_client.oauth2_revoke_token(session.get("tokens")["access_token"])

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
    # Redirect the user to the index page
    # return redirect(url_for('index'))


@app.route("/activate")
def activate():
    """
    This is an activate page, and the server resource ID is in the request argument 'server'
    """
    # Call get_login_status() to fill out the login status variables (for login/logout display)
    loginstatus = get_login_status()

    # If not logged in, redirect to the index page
    if not session.get('is_authenticated'):
        return redirect(url_for('index'))

    # Get the requested server ID
    if 'server' not in request.args:
        return redirect(url_for('index'))
    serverid = request.args.get('server')

    # Get the list of servers
    servers = get_server_list()
    if (servers == []):
        return render_template('empty-server-list.html',
                               pagetitle=app.config['APP_DISPLAY_NAME'],
                               loginstat=loginstatus)

    # Add the requested server's scope to the session scopes
    for server in servers:
        if (server['resourceid']==serverid):
            requested_scopes = session.get('scopes')
            requested_scopes += ' '+server['oauth_scope']
            session.update(
                userid=session.get('userid'),
                identity=session.get('identity'),
                fullname=session.get('fullname'),
                tokens=session.get('tokens'),
                scopes=requested_scopes,
                is_authenticated=True
            )
            
    # Start a login flow to get the new token
    return redirect(url_for('login'))


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
    if not (session.get('is_authenticated') or session.get('preauthenticated')):
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
         loginstat["tokens"] = session.get('tokens')
    return loginstat

def get_server_list():
    # Load the configured server list from the server config file, and then
    # add any access tokens from the current session.

    # Make sure we know the filename of the serverlist config file
    try:
         listf = app.config['APP_SERVERLIST_FILE']
    except:
         return []

    # Open the file and load its contents as a JSON object
    try:
         with open(listf, 'r') as filehandle:  
              servers = json.load(filehandle)
    except json.JSONDecodeError:
         return []
    except:
         return []

    # Make certain it's a list
    if isinstance(servers,(list,)):
        # It is a list, so go ahead and add any active tokens to the relevant entries

        # Any active ssh tokens will be in the other_tokens section of the token response
        othertokens = session.get("tokens")["other_tokens"]

        # We need n so we can change entries in the list that have active tokens
        for n in range(len(servers)):
            # Find any tokens that match this server's scope
            for tok in othertokens:
                if (tok["scope"] == servers[n]["oauth_scope"]):
                    servers[n]["access_token"] = tok["access_token"]
                    break
        return servers
    else:
        return []

def grab_keys():
    return {'akey': app.config['APP_DUO_AKEY'], 
            'ikey': app.config['APP_DUO_IKEY'], 
            'skey': app.config['APP_DUO_SKEY'],
            'host': app.config['APP_DUO_APIHOST']}

@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    # Call get_login_status() to fill out the login status variables (for login/logout display)
    loginstatus = get_login_status()

    result = grab_keys()
    sec = duo.sign_request(result['ikey'], result['skey'], result['akey'], session['userid'])
    if request.method == 'GET':
        return render_template('duoframe.html', 
                               pagetitle=app.config['APP_DISPLAY_NAME'],
                               loginstat=loginstatus, 
                               duohost=result['host'], 
                               sig_request=sec)
    if request.method == 'POST':
        user = duo.verify_response(result['ikey'], result['skey'], result['akey'], request.args.get('sig_response'))
        if user == session['userid']:
            return render_template(url_for('mfa'), user=user)

@app.route('/success', methods=['POST'])
def success():
    session.update(
        userid=session.get('userid'),
        identity=session.get('identity'),
        fullname=session.get('fullname'),
        tokens=session.get('tokens'),
        scopes=session.get('scopes'),
        is_authenticated=True
    )
    return redirect(url_for('index'))
    
# actually run the app if this is called as a script
if __name__ == '__main__':
    app.run(host='0.0.0.0',port=5000,debug=True,ssl_context=('./keys/server.crt', './keys/server.key'))

