ROOT_DIR=$(shell pwd)/
TESTDIR=$(ROOT_DIR)/tests
PHPUNIT=vendor/bin/phpunit
INFECTION_VERSION=0.15.3
INFECTION_ARGS=

all: install tests

install:
	composer update

tests: run-phpunit psalm run-infection phpcs

coverage: PUARGS="--coverage-clover=coverage.xml"
coverage: tests-unit

tests-unit: run-phpunit

run-phpunit:
	@$(PHPUNIT) $(PUARGS)

psalm:
	vendor/bin/psalm

psalm-ci:
	vendor/bin/psalm --shepherd

infection.phar:
	wget --no-check-certificate "https://github.com/infection/infection/releases/download/$(INFECTION_VERSION)/infection.phar"
	wget --no-check-certificate "https://github.com/infection/infection/releases/download/$(INFECTION_VERSION)/infection.phar.asc"
	chmod +x infection.phar

infection: infection.phar test-server run-infection kill-test-server

infection-ci: INFECTION_ARGS=--logger-github --git-diff-filter=AM
infection-ci: INFECTION_VERSION=0.23.0
infection-ci: infection

phpcs:
	vendor/bin/phpcs src/ --standard=psr12 --runtime-set ignore_warnings_on_exit true

run-infection: infection.phar
	./infection.phar $(INFECTION_ARGS)

.PHONY: tests test-server clean install infection infection-ci psalm psalm-ci phpcs
