from setuptools import setup,find_packages

setup(
    name = "firval2",
    version = "2.0.0",
    packages = find_packages(),
    author = "Nicolas Limage",
    description = "a netfilter firewall rules generator designed designed to be easy to read, write and maintain",
    license = "MIT",
    keywords = "netfilter iptables firewall",
    url = "https://github.com/nlm/firval2",
    test_suite = 'test_firval',
    classifiers = [
        'Development Status :: 1 - Alpha',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
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
            'firval = firval.main:main',
            'firval_test = firval.main:test',
        ],
    },
)
