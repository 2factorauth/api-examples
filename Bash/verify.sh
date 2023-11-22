#!/bin/bash
keyring=$(mktemp)
sig_file=$(mktemp)
keyserver=${KEYSERVER:-hkps://pgp.mit.edu}
email="security@2fa.directory"

echo "Importing public key"
gpg --no-default-keyring --keyring "$keyring" --auto-key-locate=cert --locate-keys "$email" &>/dev/null
keyid=$(gpg --no-default-keyring --keyring "$keyring" --list-keys --with-colons "$email" | awk -F: '/^pub:/ { print $5 }')
echo "Key $keyid found"

if [ -z "${IGNORE_REVOKED}" ]; then
  echo "Verifying key status"
  revoked=$(gpg --no-default-keyring --keyring "$keyring" --keyserver "$keyserver" --recv-keys "$keyid" &>/dev/null; echo $? )
  if [[ ! "$revoked" =~ ^(0|2)$ ]]; then
    echo "Public key invalid or revoked"
    exit 2
  else
    echo "Public key not revoked"
  fi
else
  echo "Skipping revocation checking"
fi

fingerprint=$(gpg --no-default-keyring --keyring "$keyring" --with-colons --list-keys "$email" | awk -F: '/^fpr:/ { print $10 }')

echo "Downloading API file"
curl "https://api.2fa.directory/v3/$1.json.sig" -so "$sig_file"

echo "Verifying API file"
valid=$(gpgv --keyring "$keyring" --output "$1.json" --status-fd 1 "$sig_file" 2>&1 | grep "VALIDSIG $fingerprint" | awk '{print $3}')

if [ "$valid" == "$fingerprint" ]; then
  echo "Valid signature"
  exit 0
else
  echo "Invalid signature"
  exit 1
fi

# Clean up files
rm "$keyring" "$sig_file"
