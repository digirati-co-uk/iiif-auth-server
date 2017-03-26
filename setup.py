from setuptools import setup

def requirements():
    """Returns requirements.txt as a list usable by setuptools"""
    import os
    here = os.path.abspath(os.path.dirname(__file__))
    reqtxt = os.path.join(here, u'requirements.txt')
    with open(reqtxt) as f:
        return f.read().split()

setup(
    name='iiifauth',
    packages=['iiifauth'],
    include_package_data=True,
    install_requires=requirements()
)