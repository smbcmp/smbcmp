from setuptools import setup, find_packages

with open("README.md", 'r') as f:
    long_description = f.read()

setup(
    name='smbcmp',
    version='0.1',
    author='Aurelien Aptel',
    author_email='aurelien.aptel@gmail.com',
    description='Diff and compare SMB network captures',
    long_description=long_description,
    long_description_content_type="text/markdown",    
    url="https://github.com/aaptel/smbcmp/",
    packages=find_packages(),
    install_requires=['curses'],
    scripts=[
        'scripts/smbcmp',
        'scripts/smbcmp-gui',
    ],
    classifiers=[
        'Programming Language :: Python :: 3 :: Only',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Topic :: System :: Networking',
        'Environment :: Console :: Curses',
    ]
)
