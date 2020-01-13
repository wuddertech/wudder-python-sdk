# python-sdk
Wudder's Python SDK. The Wudder documentation is available at [docs.wudder.tech](https://docs.wudder.tech/).

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
wudder = Wudder()
wudder.signup('email@example.org', 'p4ssw0rd', 'k3y_p4ssw0rd')
```

### Login / initialisation
```python
wudder = Wudder('email@example.org', 'p4ssw0rd', 'k3y_p4ssw0rd')
```

### Create event
```python
evhash = wudder.create_event('Title', [Fragment('clave1', 'valor1'), Fragment('clave2', 'valor2')])
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
proof = wudder.get_proof(self.evhash)
```

### Check Ethereum proof
```python
wudder.check_ethereum_proof(proof['graphn_proof'], proof['anchor_txs']['ethereum']))
```

### Check GraphN proof
```python
wudder.check_graphn_proof()
```
