# python-sdk
Wudder's Python SDK

## Installation
```bash
pip install wudder
```

## Usage

### Create account
```python
from wudder import Wudder

wudder = Wudder('https://wudder-endpoint/graphql')
wudder.signup('email@example.org', 'p4ssw0rd', 'k3y_p4ssw0rd')
```

### Create event
```python
from wudder import Wudder

wudder = Wudder('https://wudder-endpoint/graphql', 'email@example.org', 'p4ssw0rd', 'k3y_p4ssw0rd')
evhash = self.wudder.create_event('Title', [Fragment('clave1', 'valor1'), Fragment('clave2', 'valor2')])
```

### Get event
```python
from wudder import Wudder

wudder = Wudder('https://wudder-endpoint/graphql', 'email@example.org', 'p4ssw0rd', 'k3y_p4ssw0rd')
evhash = self.wudder.get_event(evhash)
```
