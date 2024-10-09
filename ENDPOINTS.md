# PRS Endpoints

Previously when working with applications within gfmodules, the actual BSN number of a person was required to gain data. Now this data is being pseudonymized by this service. See the example below.

```python
import requests

sample_bsn = "123456782"

# before this service was introduced
requests.post('https://httpbin.org/post', data={'person-identity': sample_bsn})

# with this service
requests.post('https://httpbin.org/post', data={'person-identity': prs.get_rid(sample_bsn))
```

For demonstrating purposes, we took two endpoints and added examples below.

#### `POST /base_pseudonym`
This endpoint is used for exchanging a persons' BSN number for an unique pseudonym.

```python
import requests

SAMPLE_BSN = "123456782"
ENDPOINT_URL = '<api_url>/base_pseudonym'

# Define the query parameters
params = {
    'bsn': SAMPLE_BSN,
}

# Send the request
requests.post(ENDPOINT_URL, params=params)
```

#### `POST /org_pseudonym`
This endpoint converts a BSN into a pseudonym for a specific organisation. 

```python
import requests

SAMPLE_BSN = "123456782"
SAMPLE_ORG_ID = "123"
ENDPOINT_URL = '<api_url>/org_pseudonym'

# Define the query parameters
params = {
    'bsn': SAMPLE_BSN,
    'org_id': SAMPLE_ORG_ID,
}

# Send the request
requests.post(ENDPOINT_URL, params=params)
```