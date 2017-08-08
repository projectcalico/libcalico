[![Circle CI](https://circleci.com/gh/projectcalico/libcalico.svg?style=svg)](https://circleci.com/gh/projectcalico/libcalico) [![Coverage Status](https://coveralls.io/repos/projectcalico/libcalico/badge.svg?branch=master&service=github)](https://coveralls.io/github/projectcalico/libcalico?branch=master)
# libcalico

**NOTE: Python libcalico is no longer being actively developed, and as such is likely to become out-of-date and potentially incompatible with newer Calico versions and features.  Instead, it is strongly recommended to use the Golang library, [libcalico-go](https://github.com/projectcalico/libcalico-go).  Feel free to contribute patches to this repo as the maintainers will continue to review and merge community PRs.**

Libcalico is a library for interacting with the Calico data model. It also contains code for working with veths.
* It's written in Python (though ports into other languages would be welcomed as PRs)
* It currently just talks to etcd as the backend datastore.


It's currently focused on the the container side of Calico, though again PRs are welcomed to make it more general.

## Running tests

To run tests for libcalico:

1. [Install Docker](http://docs.docker.com/installation/).
2. At the root of the libcalico directory, run:

        make test
[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/libcalico/README.md?pixel)](https://github.com/igrigorik/ga-beacon)
