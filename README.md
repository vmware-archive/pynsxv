# PyNSXv
PyNSXv is a high level python based library that exposes ready to use workflows and a CLI tool that can be used to control VMware NSX for vSphere

PyNSXv can be used in two different ways, as a library by importing the files in the /library subdirectory into your code, or as a CLI tool by executing `pynsxv`on the command line after installation. For easier installation please use PIP on your system

**More extensive documentation will follow soon, including python and shell script examples**

# dependencies
PyNSXv has the following dependencies:
- pyvmomi (https://github.com/vmware/pyvmomi)
- nsxramlclient (https://github.com/vmware/nsxramlclient)
- tabulate (https://bitbucket.org/astanin/python-tabulate) 

Please check the installation instructions of these projects if you run into installation issues

# installing PyNSXv
PyNSXv can be installed using pip:
```shell
pip install pynsxv
```
