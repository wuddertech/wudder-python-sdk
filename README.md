# python-sdk

## Installation

```bash
pip install wudder
```

## Usage

```
from wudder import Wudder, Fragment, Event
```

### Create account

```python
Wudder.signup('email@example.org', 'p4ssw0rd', private_key_password='k3y_p4ssw0rd')
```

> You can specify a custom GraphQL endpoint with the argument `endpoint`

```python
Wudder.signup('email@example.org', 'p4ssw0rd', private_key_password='k3y_p4ssw0rd', endpoint='https://api.pre.wudder.tech/graphql/')
```

### Login

```python
wudder = Wudder('email@example.org', 'p4ssw0rd', private_key_password='k3y_p4ssw0rd')
```

> Again, you can specify a custom GraphQL endpoint with the argument `endpoint`

```python
wudder = Wudder('email@example.org', 'p4ssw0rd', private_key_password='k3y_p4ssw0rd', endpoint='https://api.pre.wudder.tech/graphql/')
```

> You can sign the transactions with a custom local private key (e.g., FNMT private key in the `PKCS#12` format). Check the supported protocols and file formats at [labteral/digsig-python](https://github.com/labteral/digsig-python):
```python
wudder = Wudder('email@example.org', 'p4ssw0rd', private_key_path='private_key.p12', private_key_password='k3y_p4ssw0rd')
```

### Create trace

```python
trace_evhash = wudder.send('Title', [{'field': 'key', 'value': 'value'}])
```

### Add event to trace

```python
evhash = wudder.send('Title', [{'field': 'key', 'value': 'value'}], trace=trace_evhash)
```

### Get event

```python
event = wudder.get_event(evhash)
```

### Get trace

```python
trace = wudder.get_trace(evhash)
```

### Get proof

```python
proof = wudder.get_proof(evhash)
```

### Check Ethereum proof

```python
wudder.check_ethereum_proof(proof['proof'], proof['prefixes']['ethereum']['tx_hash']))
```

### Create a local backup of the private key

```python
import json

with open('private_key.json', 'w') as output_file:
    json.dump(wudder.private_key, output_file)
```

### Restore a local backup of the private key

```python
import json

with open('private_key.json', 'r') as input_file:
    private_key = json.load(input_file)

wudder.update_private_key(private_key, 'k3y_p4ssw0rd')
```

### Replace the private key

```python
from wudder import utils

new_private_key = utils.generate_private_key('k3y_p4ssw0rd')
wudder.update_private_key(new_private_key, 'k3y_p4ssw0rd')
```
