# python-sdk
Wudder's Python SDK. The Wudder documentation is available at [docs.wudder.tech](https://docs.wudder.tech/).

## Installation
```bash
pip install wudder
```

## Usage

```
from wudder import Wudder, Fragment, Event, utils
```

### Create account
```python
Wudder.signup('email@example.org', 'p4ssw0rd', 'k3y_p4ssw0rd')
```

### Login
```python
wudder = Wudder('email@example.org', 'p4ssw0rd', 'k3y_p4ssw0rd')
```

### Create event
```python
evhash = wudder.create_event('Title', [Fragment('key1', 'value1'), Fragment('key2', 'value2')])
```

### Get event
```python
evhash = wudder.get_event(evhash)
```

### Get trace
```python
evhash = wudder.get_trace(evhash)
```

### Get proof
```python
proof = wudder.get_proof(evhash)
```

### Check Ethereum proof
```python
wudder.check_ethereum_proof(proof['graphn_proof'], proof['anchor_txs']['ethereum']))
```

### Check GraphN proof
```python
wudder.check_graphn_proof()
```

### Create a local backup of the private key
```python
import json

with open('private_key.json', 'w') as output_file:
    json.dump(wudder.private_key, output_file)
```

### Replace the private key
```python
new_private_key = utils.generate_private_key('k3y_p4ssw0rd')
wudder.update_private_key(new_private_key)
```
