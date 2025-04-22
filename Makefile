VERSION_FILE=VERSION

release:
	@if [ -z "$(v)" ]; then \
		echo "Error: Please specify a version using 'make release v=<version>'"; \
		exit 1; \
	fi
	echo "$(v)" > $(VERSION_FILE)
	git add $(VERSION_FILE)
	git commit -m "Release version $(v)"
	git tag "$(v)"
	git push
	git push --tags