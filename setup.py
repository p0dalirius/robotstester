import shutil
import os
from setuptools import setup

with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

with open('requirements.txt', 'r', encoding='utf-8') as f:
    content = f.readlines()
    requirements = [x.strip() for x in content]

shutil.copyfile('robotstester.py', 'robotstester')

setup(
    name='robotstester',
    version='1.0',
    author='Podalirius',
    description='HTTP verb tampering & methods enumeration  ',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/p0dalirius/robotstester',
    classifiers=[
        'Environment :: Console'
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
    ],
    python_requires='>=3.6',
    install_requires=requirements,
    scripts=["robotstester"]
    # entry_points = {
    #     'console_scripts' : ['robotstester=robotstester:main']
    # }
)
os.remove("robotstester")
