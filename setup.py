from setuptools import setup
import io

def read(*filenames, **kwargs):
    encoding = kwargs.get('encoding', 'utf-8')
    sep = kwargs.get('sep', '\n')
    buf = []
    for filename in filenames:
        with io.open(filename, encoding=encoding) as f:
            buf.append(f.read())
    return sep.join(buf)

long_description = read('README.rst')

setup(
    name='PyNSXv',
    version='0.3',
    packages=['pynsxv'],
    package_data={'pynsxv':['*'], 'pynsxv':['library/*']},
    url='http://github.com/vmware/pynsxv',
    license='MIT',
    author='Dimitri Desmidt, Emanuele Mazza, Yves Fauser',
    author_email='yfauser@vmware.com',
    description='PyNSXv is a higher level python based library and CLI tool to control NSX for vSphere',
    long_description=long_description,
    classifiers=[
    'Development Status :: 5 - Production/Stable',
    'Intended Audience :: End Users/Desktop',
    'Topic :: Utilities',
    'License :: OSI Approved :: MIT License',
    'Programming Language :: Python :: 2.7'],
    install_requires=['nsxramlclient>=2.0', 'pyvmomi', 'tabulate'],
    entry_points={
        'console_scripts': ['pynsxv = pynsxv.cli:main']
    }
)
