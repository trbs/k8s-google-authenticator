from setuptools import setup

requires = [
    "PyYAML",  # >=3.12
    "six",  # >=1.10.0
    "requests",  # >=2.18.1
]

setup(
    name='k8s-google-authenticator',
    version='1.0.2',
    description="Kubernetes Google OpenID authentication helper",
    url='http://github.com/trbs/k8s-google-authenticator',
    author='trbs',
    author_email='trbs@trbs.net',
    keywords='kubernetes k8s google authentication authenticator openid connector kubectl config',
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'Operating System :: OS Independent',
        'Topic :: Internet',
        'Topic :: Utilities',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
    ],
    license='MIT',
    packages=['k8s_google_authenticator'],
    entry_points={
        'console_scripts': [
            'k8s-google-authenticator = k8s_google_authenticator.main:main',
        ]
    },
    tests_require=requires,
    install_requires=requires,
)
