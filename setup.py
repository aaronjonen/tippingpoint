from setuptools import setup
with open("README.md","r") as fh:
    long_description = fh.read()

setup(
    name='tippingpoint',
    version="0.3",
    packages=[
        "tippingpoint",

        "unittest"
    ],
    license="MIT",
    long_description=long_description,
    install_requires=[
        "requests",
        'scapy',
        "urllib3"
    ],
    url="https://github.com/aaronjonen/tippingpoint.git",
    author="aaron jonen",
    author_email="ajonen@mailcan.com",
    include_package_data=True,
    zip_safe=False
)
