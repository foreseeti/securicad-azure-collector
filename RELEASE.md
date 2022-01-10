# Release securiCAD AWS Collector

This file describes how to make release builds of `securicad-azure-collector` and how to publish them to [PyPI](https://pypi.org).

To make a release, perform the following steps:

1. Make a release commit and push it to a new branch
2. Make a pull request to `master` and get it approved and merged
3. Make a release tag for the merged pull request
4. Build distribution files
5. Publish distribution files

### 1. Make a release commit and push it to a new branch

The release commit shall contain the following changes:

- Updated version number in `securicad/azure_collector/__init__.py`
- Updated dependencies in `requirements.txt` and `dev-requirements.txt`

Test that everything still works with the new dependencies.

The name of the new branch doesn't matter, since it will be deleted after the release commit has been merged to `master`, but the convention for branch names is `<user-name>/<branch-name>`, e.g. `Gyllingen/release`.

The commit message shall be `Release <version>`, e.g. `Release 1.0.1`.

```
$ git checkout -b Gyllingen/release
$ sed -i 's/^__version__ = "[^"]*"$/__version__ = "1.0.1"/' securicad/azure_collector/__init__.py
$ ./tools/scripts/create_requirements.sh
$ git add securicad/azure_collector/__init__.py requirements.txt dev-requirements.txt
$ git commit -m "Release 1.0.1"
$ git push origin Gyllingen/release
```

### 2. Make a pull request to `master` and get it approved and merged

Go to the repository on GitHub, click `Pull requests`, and then `New pull request`. Make sure that `base` is set to `master`, and set `compare` to your branch. Click `Create pull request`, add appropriate `Reviewers`, and add yourself as `Assignees`.

### 3. Make a release tag for the merged pull request

Once your pull request has been merged, you need to fetch the new merged commit in `master` to create the release tag:

```
$ git checkout master
$ git fetch
$ git merge --ff-only
$ git tag release/1.0.1
$ git push origin release/1.0.1
```

### 4. Build distribution files

Make sure that the repo is clean:

```
git status --ignored
```

Create and activate a virtual Python environment:

```
./tools/scripts/create_venv.sh
. venv/bin/activate
```

Build source and wheel distribution:

```
python -m build
```

There should now be two files under the directory `dist/`: `securicad-azure-collector-1.0.1.tar.gz` and `securicad_azure_collector-1.0.1-py3-none-any.whl`.

### 5. Publish distribution files

Create `~/.pypirc` with the following content:

```
[distutils]
index-servers =
  securicad-azure-collector
  securicad-azure-collector-test

[securicad-azure-collector]
repository = https://upload.pypi.org/legacy/
username = __token__
password = pypi-****

[securicad-azure-collector-test]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-****
```

Publish distribution files to testpypi:

```
twine upload --repository securicad-azure-collector-test dist/*
```

Publish distribution files to pypi:

```
twine upload --repository securicad-azure-collector dist/*
```
