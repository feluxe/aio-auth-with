from setuptools import setup, find_packages
from codecs import open
from buildlib import yaml

with open('README.md') as f:
    long_description = f.read()

config = yaml.loadfile('Project')

setup(
    name=config['public_name'],
    version=config['version'],
    author=config['author'],
    author_email=config['author_email'],
    maintainer=config['maintainer'],
    maintainer_email=config['maintainer_email'],
    url=config['url'],
    description=config['description'],
    long_description=long_description,
    download_url=config['url'] + '/tarball/' + config['version'],
    license=config['license'],
    keywords=config['keywords'],

    include_package_data=True,
    platforms=config['pypi']['platforms'],
    classifiers=config['pypi']['classifiers'],
    install_requires=config['pypi']['install_requires'],
    packages=find_packages(where='.', exclude=(
    'tests', 'tests.*', 'venv-aio-auth-with', 'venv-aio-auth-with.*')),
    package_dir=config['pypi']['package_dir'],
    package_data=config['pypi']['package_data'],
    data_files=config['pypi']['data_files'],
    entry_points=config['pypi']['entry_points'],
    tests_require=config['pypi']['tests_require']
)
