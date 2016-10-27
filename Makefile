.PHONY: all test test_image ut ut-circle clean setup-env

###############################################################################
# Common build variables
# Path to the sources.
# Default value: directory with Makefile
SOURCE_DIR?=$(dir $(lastword $(MAKEFILE_LIST)))
SOURCE_DIR:=$(abspath $(SOURCE_DIR))

BUILD_CONTAINER_NAME?=calico/build:latest
TEST_CONTAINER_NAME?=calico/test:latest

PYCALICO=$(wildcard $(SOURCE_DIR)/calico_containers/pycalico/*.py)
BUILD_FILES=Dockerfile build-requirements-frozen.txt

TEST_CONTAINER_FILES=$(shell find calico_test/ -type f ! -name '*.created')

WHEEL_VERSION=0.1.0

default: all
all: test
wheel: dist/pycalico-$(WHEEL_VERSION)-py2-none-any.whl
test_image: calico_test.created ## Create the calico/test image
test: ut
build-container: calicobuild.created
calico/build: build-container
calico/test: calico_test.created

update-frozen:
	cp build-requirements.txt build-requirements-frozen.txt
	docker build -t $(BUILD_CONTAINER_NAME) .
	docker run --rm $(BUILD_CONTAINER_NAME) pip freeze | grep -v pycalico > build-requirements-frozen.txt

calicobuild.created: $(BUILD_FILES) $(PYCALICO)
	docker build -t $(BUILD_CONTAINER_NAME) .
	docker build -f Dockerfile.build_wheezy -t $(BUILD_CONTAINER_NAME)-wheezy .
	touch calicobuild.created

dist/pycalico-$(WHEEL_VERSION)-py2-none-any.whl: $(PYCALICO)
	mkdir -p dist
	chmod 777 dist
	python setup.py bdist_wheel

calico_test.created: $(TEST_CONTAINER_FILES)
	docker build -f Dockerfile.calico_test -t $(TEST_CONTAINER_NAME) .
	touch calico_test.created

ut: calico_test.created
	docker run --rm -v $(SOURCE_DIR)/calico_containers:/code $(TEST_CONTAINER_NAME) \
                nosetests tests/unit  -c nose.cfg


ut-circle: calico_test.created
	# Test this locally using CIRCLE_TEST_REPORTS=/tmp COVERALLS_REPO_TOKEN=bad make ut-circle
	# Can't use --rm on circle
	# Circle also requires extra options for reporting.
	docker run \
        -v $(SOURCE_DIR):/code \
        -v $(CIRCLE_TEST_REPORTS):/circle_output \
        -e COVERALLS_REPO_TOKEN=$(COVERALLS_REPO_TOKEN) \
        $(TEST_CONTAINER_NAME) \
        sh -c '\
        cd calico_containers; nosetests tests/unit -c nose.cfg \
        --with-xunit --xunit-file=/circle_output/output.xml; RC=$$?;\
        [[ ! -z "$$COVERALLS_REPO_TOKEN" ]] && coveralls || true; exit $$RC'


clean:
	-rm -f *.created
	find . -name '*.pyc' -exec rm -f {} +
	-rm -rf build
	-rm -rf calico_containers/pycalico.egg-info/
	-docker rm -f calico-build
	-docker rmi $(BUILD_CONTAINER_NAME) $(BUILD_CONTAINER_NAME)-wheezy
	-docker rmi $(TEST_CONTAINER_NAME)

setup-env:
	virtualenv venv
	venv/bin/pip install --upgrade -r requirements.txt
	@echo "run\n. venv/bin/activate"
