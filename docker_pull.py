import os
import sys
import gzip
from io import BytesIO
import json
import hashlib
import shutil
import requests
import tarfile
import urllib3
import yaml
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

urllib3.disable_warnings()

if len(sys.argv) != 2:
    print('Usage:\n\tdocker_pull.py [registry/][repository/]image[:tag|@digest]\n')
    exit(1)

with open('config.yaml', 'r') as file:
    config = yaml.safe_load(file)

proxies = config['proxies']
timeout = config.get('timeout', 10)  

# create session
session = requests.Session()
retries = Retry(total=2, backoff_factor=1, status_forcelist=[502, 503, 504])
session.mount('https://', HTTPAdapter(max_retries=retries))

# send request with proxy
def try_request(url, headers=None, stream=False, verify=False):
    for proxy in proxies[:]:
        try:
            proxy_dict = {
                "http": proxy,
                "https": proxy,
            }
            response = session.get(url, headers=headers, stream=stream, proxies=proxy_dict, timeout=timeout, verify=verify)
            if response.status_code == 200:
                return response
            elif response.status_code == 401 and 'WWW-Authenticate' in response.headers:
                return response
            else:
                print(f"[-] Proxy {proxy} returned status code {response.status_code} for URL: {url}")
        except Exception as e:
            print(f"[-] Proxy {proxy} failed for URL: {url} with error: {e}, removing proxy from list")
        	# del proxies[proxy]
            proxies.remove(proxy)
    raise Exception("All proxies failed")

# get image info
repo = 'library'
tag = 'latest'
imgparts = sys.argv[1].split('/')
try:
    img, tag = imgparts[-1].split('@')
except ValueError:
    try:
        img, tag = imgparts[-1].split(':')
    except ValueError:
        img = imgparts[-1]
if len(imgparts) > 1 and ('.' in imgparts[0] or ':' in imgparts[0]):
    registry = imgparts[0]
    repo = '/'.join(imgparts[1:-1])
else:
    registry = 'registry-1.docker.io'
    if len(imgparts[:-1]) != 0:
        repo = '/'.join(imgparts[:-1])
    else:
        repo = 'library'
repository = '{}/{}'.format(repo, img)

# get auth url and registry service
auth_url = 'https://auth.docker.io/token'
reg_service = 'registry.docker.io'
resp = try_request('https://{}/v2/'.format(registry))
if resp.status_code == 401:
    auth_url = resp.headers['WWW-Authenticate'].split('"')[1]
    try:
        reg_service = resp.headers['WWW-Authenticate'].split('"')[3]
    except IndexError:
        reg_service = ""

# get auth head
def get_auth_head(type):
    resp = try_request('{}?service={}&scope=repository:{}:pull'.format(auth_url, reg_service, repository))
    access_token = resp.json()['token']
    auth_head = {'Authorization': 'Bearer ' + access_token, 'Accept': type}
    return auth_head

# progress bar
def progress_bar(ublob, nb_traits):
    sys.stdout.write('\r' + ublob[7:19] + ': Downloading [')
    for i in range(0, nb_traits):
        if i == nb_traits - 1:
            sys.stdout.write('>')
        else:
            sys.stdout.write('=')
    for i in range(0, 49 - nb_traits):
        sys.stdout.write(' ')
    sys.stdout.write(']')
    sys.stdout.flush()

# get manifest
auth_head = get_auth_head('application/vnd.docker.distribution.manifest.v2+json')
resp = try_request('https://{}/v2/{}/manifests/{}'.format(registry, repository, tag), headers=auth_head, verify=False)
if resp.status_code != 200:
    print('[-] Cannot fetch manifest for {} [HTTP {}]'.format(repository, resp.status_code))
    print(resp.content)
    auth_head = get_auth_head('application/vnd.docker.distribution.manifest.list.v2+json')
    resp = try_request('https://{}/v2/{}/manifests/{}'.format(registry, repository, tag), headers=auth_head, verify=False)
    if resp.status_code == 200:
        print('[+] Manifests found for this tag (use the @digest format to pull the corresponding image):')
        manifests = resp.json()['manifests']
        for manifest in manifests:
            for key, value in manifest["platform"].items():
                sys.stdout.write('{}: {}, '.format(key, value))
            print('digest: {}'.format(manifest["digest"]))
    exit(1)
layers = resp.json()['layers']

# create image structure
imgdir = 'tmp_{}_{}'.format(img, tag.replace(':', '@'))
os.mkdir(imgdir)
print('Creating image structure in: ' + imgdir)

config = resp.json()['config']['digest']
confresp = try_request('https://{}/v2/{}/blobs/{}'.format(registry, repository, config), headers=auth_head, verify=False)
file = open('{}/{}.json'.format(imgdir, config[7:]), 'wb')
file.write(confresp.content)
file.close()

content = [{
    'Config': config[7:] + '.json',
    'RepoTags': [],
    'Layers': []
}]
if len(imgparts[:-1]) != 0:
    content[0]['RepoTags'].append('/'.join(imgparts[:-1]) + '/' + img + ':' + tag)
else:
    content[0]['RepoTags'].append(img + ':' + tag)

empty_json = '{"created":"1970-01-01T00:00:00Z","container_config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false, \
    "AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false, "StdinOnce":false,"Env":null,"Cmd":null,"Image":"", \
    "Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":null}}'

# Build layer folders
parentid = ''
for layer in layers:
    ublob = layer['digest']
    fake_layerid = hashlib.sha256((parentid + '\n' + ublob + '\n').encode('utf-8')).hexdigest()
    layerdir = imgdir + '/' + fake_layerid
    os.mkdir(layerdir)

    # create VERSION file
    file = open(layerdir + '/VERSION', 'w')
    file.write('1.0')
    file.close()

    # creating layer.tar file
    sys.stdout.write(ublob[7:19] + ': Downloading...')
    sys.stdout.flush()
    auth_head = get_auth_head('application/vnd.docker.distribution.manifest.v2+json') 
    bresp = try_request('https://{}/v2/{}/blobs/{}'.format(registry, repository, ublob), headers=auth_head, stream=True, verify=False)
    if bresp.status_code != 200:
        bresp = try_request(layer['urls'][0], headers=auth_head, stream=True)
        if bresp.status_code != 200:
            print('\rERROR: Cannot download layer {} [HTTP {}]'.format(ublob[7:19], bresp.status_code, bresp.headers['Content-Length']))
            print(bresp.content)
            exit(1)
    bresp.raise_for_status()
    unit = int(bresp.headers['Content-Length']) / 50
    acc = 0
    nb_traits = 0
    progress_bar(ublob, nb_traits)
    with open(layerdir + '/layer_gzip.tar', "wb") as file:
        for chunk in bresp.iter_content(chunk_size=8192):
            if chunk:
                file.write(chunk)
                acc = acc + 8192
                if acc > unit:
                    nb_traits = nb_traits + 1
                    progress_bar(ublob, nb_traits)
                    acc = 0
    sys.stdout.write("\r{}: Extracting...{}".format(ublob[7:19], " " * 50))
    sys.stdout.flush()
    with open(layerdir + '/layer.tar', "wb") as file:
        unzLayer = gzip.open(layerdir + '/layer_gzip.tar', 'rb')
        shutil.copyfileobj(unzLayer, file)
        unzLayer.close()
    os.remove(layerdir + '/layer_gzip.tar')
    print("\r{}: Pull complete [{} bytes]".format(ublob[7:19], bresp.headers['Content-Length']))
    content[0]['Layers'].append(fake_layerid + '/layer.tar')

    file = open(layerdir + '/json', 'w')
    if layers[-1]['digest'] == layer['digest']:
        json_obj = json.loads(confresp.content)
        del json_obj['history']
        try:
            del json_obj['rootfs']
        except:
            del json_obj['rootfS']
    else:
        json_obj = json.loads(empty_json)
    json_obj['id'] = fake_layerid
    if parentid:
        json_obj['parent'] = parentid
    parentid = json_obj['id']
    file.write(json.dumps(json_obj))
    file.close()

file = open(imgdir + '/manifest.json', 'w')
file.write(json.dumps(content))
file.close()

if len(imgparts[:-1]) != 0:
    content = {'/'.join(imgparts[:-1]) + '/' + img: {tag: fake_layerid}}
else: # when pulling only an img (without repo and registry)
    content = {img: {tag: fake_layerid}}
file = open(imgdir + '/repositories', 'w')
file.write(json.dumps(content))
file.close()

docker_tar = repo.replace('/', '_') + '_' + img + '.tar'
sys.stdout.write("Creating archive...")
sys.stdout.flush()
tar = tarfile.open(docker_tar, "w")
tar.add(imgdir, arcname=os.path.sep)
tar.close()
shutil.rmtree(imgdir)
print('\rDocker image pulled: ' + docker_tar)
