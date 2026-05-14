RELEASE_TAG ?= $(shell git tag --list --sort=-v:refname | awk -F. 'NF == 3 && $$1 ~ /^[0-9]+$$/ && $$2 ~ /^[0-9]+$$/ && $$3 ~ /^[0-9]+$$/ { printf "%d.%d.%d", $$1, $$2, $$3 + 1; found=1; exit } END { if (!found) printf "0.0.1" }')
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
	@echo "Creating release $(RELEASE_TAG)"
	git tag -a $(RELEASE_TAG) -m "Release $(RELEASE_TAG)"
	git push $(RELEASE_REMOTE) $(RELEASE_TAG)
