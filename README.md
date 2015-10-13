[![Circle CI](https://circleci.com/gh/projectcalico/libcalico.svg?style=svg)](https://circleci.com/gh/projectcalico/libcalico) [![Coverage Status](https://coveralls.io/repos/projectcalico/libcalico/badge.svg?branch=master&service=github)](https://coveralls.io/github/projectcalico/libcalico?branch=master)
# libcalico

Libcalico is a library for interacting with the Calico data model. It also contains code for working with veths.
* It's written in Python (though ports into other languages would be welcomed as PRs)
* It currently just talks to etcd as the backend datastore.


It's currently focused on the the container side of Calico, though again PRs are welcomed to make it more general.

## Running tests

To run tests for libcalico:

1. [Install Docker](http://docs.docker.com/installation/).
2. At the root of the libcalico directory, run:

        make test
