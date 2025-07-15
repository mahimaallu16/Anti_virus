import os
import requests
import zipfile
import shutil
import time

yara_rules_dir = 'signatures'
yara_rules_github_zip = 'https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip'
malpedia_yara_zip = 'https://malpedia.caad.fkie.fraunhofer.de/api/get/yara/all'
malpedia_api_key = os.environ.get('MALPEDIA_API_KEY')  # Optional, for private access

def download_and_extract_zip(url, dest_dir, headers=None):
    local_zip = 'temp_yara.zip'
    with requests.get(url, stream=True, headers=headers) as r:
        r.raise_for_status()
        with open(local_zip, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
    with zipfile.ZipFile(local_zip, 'r') as zip_ref:
        zip_ref.extractall(dest_dir)
    os.remove(local_zip)

def update_yara_rules():
    print('Updating YARA rules...')
    temp_dir = 'temp_yara_rules'
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    os.makedirs(temp_dir, exist_ok=True)

    # Download YARA-Rules GitHub
    print('Fetching YARA-Rules from GitHub...')
    download_and_extract_zip(yara_rules_github_zip, temp_dir)
    # Copy all .yar files to signatures/
    for root, dirs, files in os.walk(temp_dir):
        for file in files:
            if file.endswith('.yar'):
                shutil.copy2(os.path.join(root, file), yara_rules_dir)

    # Download malpedia YARA rules
    print('Fetching malpedia YARA rules...')
    headers = {'Authorization': f'Bearer {malpedia_api_key}'} if malpedia_api_key else None
    try:
        download_and_extract_zip(malpedia_yara_zip, temp_dir, headers=headers)
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith('.yar'):
                    shutil.copy2(os.path.join(root, file), yara_rules_dir)
    except Exception as e:
        print('Could not fetch malpedia rules:', e)

    shutil.rmtree(temp_dir)
    print('YARA rules updated!')

if __name__ == '__main__':
    update_yara_rules() 