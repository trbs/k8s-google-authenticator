import os
import json
import yaml
import random
import shutil
import hashlib
import argparse
import requests
import platform
import subprocess
from . import __version__
from six.moves import input
try:
    from shutil import which
except ImportError:
    which = None
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper


# see:  https://developers.google.com/identity/protocols/OAuth2InstalledApp
#       https://developers.google.com/identity/protocols/googlescopes#google-sign-in
OAUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth?client_id={client_id}&redirect_uri=urn:ietf:wg:oauth:2.0:oob&response_type=code&scope=openid+email+profile&state={state_nonce}&prompt=consent%20select_account&access_type=offline"
TOKEN_URL = "https://www.googleapis.com/oauth2/v4/token"
USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
IDP_ISSUER_URL = "https://accounts.google.com"


def create_parser():
    description = """Authenticate, retreive tokens and update ~/.kube/config"""
    default_kube_config_filename = '~/.kube/config'

    parser = argparse.ArgumentParser(description=description)

    parser.add_argument('cluster_name', metavar='cluster-name', help="Clustername as specified in ~/.kube/config")
    parser.add_argument('context_name', metavar='context-name', nargs='?', help="If context name is not given it will be generated as clustername + username")
    parser.add_argument('--version', action='version', version='%%(prog)s %s' % __version__)
    parser.add_argument('--kube-config', dest='kube_config_file', default=None, type=argparse.FileType('r'), help="Path to kube config (default: %s)" % default_kube_config_filename)
    parser.add_argument('-f', dest='configfile', default=None, type=argparse.FileType('r'), help="Google client-secret json file")
    parser.add_argument('--client-id', dest='client_id', default=os.environ.get('GOOGLE_CLIENT_ID'), help="Google client-id (can also be set as GOOGLE_CLIENT_ID environment variable)")
    parser.add_argument('--client-secret', dest='client_secret', default=os.environ.get('GOOGLE_CLIENT_SECRET'), help="Google client-secret (can also be set as GOOGLE_CLIENT_SECRET environment variable)")
    # parser.add_argument('--user-name-format', dest='user_name_format', default='context-name', help='How user name is formatted for kube config. The unique prefixed options combine name or email with clustername to make it unique per context. (Default: context-name)',
    #                     choices=["context-name", "unique-name", "unique-email", "name", "email"])
    # parser.add_argument('-v', '--verbose', dest="verbose", action="store_true", default=False, help="Verbosity")
    # parser.add_argument('--oauth-url', dest='oauth_url', help="Set oauth url (Default: %s)" % oauth_url)

    browser_parser = parser.add_mutually_exclusive_group(required=False)
    browser_parser.add_argument('--browser', dest='open_browser', action='store_true', help="Automatically open browser to authenticate with Google (Default)")
    browser_parser.add_argument('--no-browser', dest='open_browser', action='store_false', help="Do not open browser to authenticate with Google")

    kubeconfig_parser = parser.add_mutually_exclusive_group(required=False)
    kubeconfig_parser.add_argument('-u', '--update-kube-config', dest='update_kube_config', action='store_true', help="Automatically update ~/.kube/config (Default)")
    kubeconfig_parser.add_argument('-n', '--no-update-kube-config', dest='update_kube_config', action='store_false', help="Do not update ~/.kube/config")

    override_config_parser = parser.add_mutually_exclusive_group(required=False)
    override_config_parser.add_argument('--overwrite-config', dest='overwrite_config', action='store_true', help="Overwrite kube config context if already exists")
    override_config_parser.add_argument('--no-overwrite-config', dest='overwrite_config', action='store_false', help="Do not overwrite kube config context (Default)")

    parser.set_defaults(
        kube_config_file=os.path.expanduser(default_kube_config_filename),
        open_browser=True,
        update_kube_config=True,
        overwrite_config=False,
    )
    return parser


def check_cluster_name_exists(cluster_name, kube_config, parser):
    if 'clusters' not in kube_config:
        parser.error("'clusters' not found in kube config")

    found_names = []
    for cluster in kube_config['clusters']:
        name = cluster.get('name')
        if name == cluster_name:
            return
        found_names.append(name)

    parser.error("Cluster name '%s' not found in kube config, available: %s" % (cluster_name, found_names))


def check_context_name_already_exists(context_name, kube_config, parser):
    if 'contexts' not in kube_config:
        parser.error("'contexts' not found in kube config")

    for context in kube_config['contexts']:
        name = context.get('name')
        if name == context_name:
            parser.error("Context name '%s' already exists in kube config, exiting..." % context_name)


def check_user_name_already_exists(user_name, kube_config, parser):
    if 'users' not in kube_config:
        parser.error("'users' not found in kube config")

    for user in kube_config['users']:
        name = user.get('name')
        if name == user_name:
            parser.error("User name '%s' already exists in kube config, exiting..." % user_name)


def load_client_id_and_secret(args, parser):
    configfile = args.configfile
    client_id = args.client_id
    client_secret = args.client_secret

    if not configfile and not client_id:
        parser.error("Either -f or --client-id or CLIENT_ID environment variable must be given to continue...")

    if configfile and client_id:
        parser.error("Both -f and --client-id are set, only one can be set...")

    if configfile:
        config = json.load(configfile)
        try:
            client_id = config['installed']['client_id']
            client_secret = config['installed']['client_secret']
        except KeyError:
            parser.error("Cannot find 'client_id' and 'client_secret' in Google config file.")
    else:
        if not client_id or not client_secret:
            parser.error("Both --client-id and --client-secret must be set")

    return client_id, client_secret


def do_authentication(client_id, state_nonce, args, parser):
    try:
        oauth_url = OAUTH_URL.format(
            client_id=client_id,
            state_nonce=state_nonce,
        )
    except KeyError as exc:
        parser.error("Invalid parameter for oauth_url: %s, only 'client_id' and 'state_nonce' are supported." % exc)

    system = platform.system()
    open_cmd = None
    if system == "Darwin":
        open_cmd = "open"
    else:
        open_cmd = "xdg-open"

    if which and args.open_browser and not which(open_cmd):
        print("Command '%s' not found on this system. Disabling automatically opening browser.\n" % open_cmd)
        args.open_browser = False

    if args.open_browser:
        try:
            subprocess.check_call([open_cmd, oauth_url])
        except Exception as exc:
            parser.error("Unable to automatically open browser, please try with --no-browser")
    else:
        print("Please open a new browser window and login using the following url:")
        print("\t%s" % oauth_url)


def get_code(parser):
    try:
        code = input("Please paste the code you got here: ")
    except KeyboardInterrupt:
        parser.error("Aborted...")
    code = code.strip()
    return code


def get_tokens(client_id, client_secret, code, parser):
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
    }
    r = requests.post(TOKEN_URL, data=data)
    try:
        r.raise_for_status()
    except Exception as exc:
        if exc.response.status_code == 400:
            parser.error("Authentication denied, code failed to validate. Please try again.")
        raise
    return r.json()


def get_userinfo(tokens, parser):
    params = {
        'alt': 'json',
        'access_token': tokens['access_token'],
    }
    r = requests.get(USERINFO_URL, params=params)
    try:
        r.raise_for_status()
    except Exception as exc:
        if exc.response.status_code == 400:
            parser.error("Authentication denied, code failed to validate. Please try again.")
        raise
    return r.json()


def main():
    parser = create_parser()
    args = parser.parse_args()

    state_nonce = hashlib.sha1(b"%f" % random.random()).hexdigest()

    cluster_name = args.cluster_name
    context_name = args.context_name
    overwrite_config = args.overwrite_config
    kube_config_file_name = args.kube_config_file.name

    kube_config_mtime = os.path.getmtime(kube_config_file_name)
    kube_config = yaml.load(args.kube_config_file, Loader=Loader)
    args.kube_config_file.close()

    check_cluster_name_exists(cluster_name, kube_config, parser)

    if context_name and not overwrite_config:
        check_context_name_already_exists(context_name, kube_config, parser)
        check_user_name_already_exists(context_name, kube_config, parser)

    client_id, client_secret = load_client_id_and_secret(args, parser)

    do_authentication(client_id, state_nonce, args, parser)
    code = get_code(parser)
    tokens = get_tokens(client_id, client_secret, code, parser)
    userinfo = get_userinfo(tokens, parser)
    google_user_name = userinfo['name'].lower().replace(" ", ".")

    if not google_user_name:
        parser.error("Could not find user name from Google profile.")

    if not context_name:
        context_name = "{cluster_name}-{google_user_name}".format(
            cluster_name=cluster_name,
            google_user_name=google_user_name,
        )
        if not overwrite_config:
            check_user_name_already_exists(context_name, kube_config, parser)
            check_context_name_already_exists(context_name, kube_config, parser)

    kube_user_obj = {
        "name": context_name,
        "user": {
            "auth-provider": {
                "name": "oidc",
                "config": {
                    "client-id": client_id,
                    "client-secret": client_secret,
                    "id-token": tokens['id_token'],
                    "refresh-token": tokens['refresh_token'],
                    "idp-issuer-url": IDP_ISSUER_URL,
                },
            },
        },
    }

    kube_context_obj = {
        'name': context_name,
        'context': {
            'cluster': cluster_name,
            'user': context_name,
        },
    }

    kube_config['users'].append(kube_user_obj)
    kube_config['contexts'].append(kube_context_obj)

    if args.update_kube_config:
        if kube_config_mtime != os.path.getmtime(kube_config_file_name):
            parser.error("%s has changed since we first read it. Exiting..." % kube_config_file_name)

        print("Creating backup of kube config.")
        shutil.copy2(kube_config_file_name, "%s.bak-k8s_google_authenticator" % kube_config_file_name)
        print("Writing updated kube config.")
        with open(kube_config_file_name, "w") as f:
            yaml.dump(kube_config, f, Dumper=Dumper, default_flow_style=False)
    else:
        print("\nPlease add these two sections to your kube config:\n")
        print("contexts:")
        print(yaml.dump([kube_context_obj], Dumper=Dumper, default_flow_style=False))
        print("users:")
        print(yaml.dump([kube_user_obj], Dumper=Dumper, default_flow_style=False))

    print("\nThe new context can be used with:\n")
    print("  $ kubectl --context %s cluster-info" % context_name)


if __name__ == "__main__":
    main()
