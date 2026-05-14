RELEASE_TAG ?= 1.0.0
RELEASE_REMOTE ?= origin

.PHONY: ci release
ci:
	bash -n check-encrypted-files test_check_encrypted_files.sh
	bash test_check_encrypted_files.sh
	editorconfig-checker
	yamllint .
	npx markdownlint-cli2 "**/*.{md,markdown}"
	go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7

release:
	git tag -a $(RELEASE_TAG) -m "Release $(RELEASE_TAG)"
	git push $(RELEASE_REMOTE) $(RELEASE_TAG)
