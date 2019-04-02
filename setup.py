from setuptools import setup, find_packages

setup(
    name='unitrail',
    version='0.0.3',
    description='CLI for autotests connection with Testrail',
    long_description='# UniTrail',
    long_description_content_type='text/markdown',
    url='https://github.com/mettizik/unitrail',
    author='Mokych Andrey',
    author_email='mokych.andrey@apriorit.com',
    keywords='testrail junit autotests report',
    packages=find_packages(exclude=['.vscode', '.sonarlint', 'docs', 'tests']),
    python_requires='>=3.0',
    install_requires=['junitparser', 'requests'],
    license='MIT',
    entry_points={
        'console_scripts': [
            'unitrail=unitrail.__main__:main',
        ],
    }
)
