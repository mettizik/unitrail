from setuptools import setup, find_packages
from os import path
from io import open

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='unitrail',
    version='0.0.1',
    description='CLI for autotests connection with Testrail',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/mettizik/unitrail',
    author='Mokych Andrey',
    author_email='mokych.andrey@apriorit.com',
    keywords='testrail junit autotests report',
    packages=find_packages(exclude=['.vscode', '.sonarlint', 'docs', 'tests']),
    python_requires='>=3.0',
    install_requires=['junitparser', 'requests'],
    entry_points={
        'console_scripts': [
            'unitrail=unitrail.__main__:main',
        ],
    }
)
