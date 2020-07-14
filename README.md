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

> You can specify a custom GraphQL endpoint with the argument `graphql_endpoint`

```python
Wudder.signup('email@example.org', 'p4ssw0rd', 'k3y_p4ssw0rd', graphql_endpoint='https://api.testnet.wudder.tech/graphql/')
```

### Login

```python
wudder = Wudder('email@example.org', 'p4ssw0rd', 'k3y_p4ssw0rd')
```

> Again, you can specify a custom GraphQL endpoint with the argument `graphql_endpoint`

```python
wudder = Wudder('email@example.org', 'p4ssw0rd', 'k3y_p4ssw0rd', graphql_endpoint='https://api.testnet.wudder.tech/graphql/')
```

### Create trace
```python
evhash = wudder.create_trace('Title', [Fragment('key1', 'value1'), Fragment('key2', 'value2')])
```

### Add event to trace
```python
evhash2 = wudder.add_event(evhash, 'Title', [Fragment('key1', 'value1'), Fragment('key2', 'value2')])
```

### Create proof
> Currently it's an alias for `create_trace`
```python
evhash = wudder.create_proof('Title', [Fragment('key1', 'value1'), Fragment('key2', 'value2')])
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
wudder.check_ethereum_proof(proof['graphn_proof'], proof['anchor_txs']['ethereum']))
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
