from setuptools import setup,find_packages

setup(
    name = "firval",
    version = "1.1",
    packages = find_packages(),
    author = "Nicolas Limage",
    description = "a netfilter firewall rules generator designed designed to be easy to read, write and maintain",
    license = "GPL",
    keywords = "netfilter iptables firewall",
    url = "https://github.com/nlm/firval",
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Topic :: System :: Networking :: Firewalls',
    ],
    install_requires = [
        'PyYAML>=3.0',
        'netaddr>=0.7.0',
        'voluptuous>=0.8.6',
    ],
    entry_points = {
        'console_scripts': [
            'firval = firval:main',
        ],
    },
)
